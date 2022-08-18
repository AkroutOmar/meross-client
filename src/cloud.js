import { createHash } from 'crypto'
import got from 'got'
import { EventEmitter } from 'events'
import  { v4 as uuidv4 } from 'uuid'
import * as mqtt from 'mqtt'
import * as request from 'request'

import { MerossCloudDevice } from './device.js'
import { MerossCloudHubDevice } from './hub.js'
import { encodeParams, generateRandomString } from './utils.js'
import { getErrorMessage } from './errorcodes.js'

const SECRET = '23x17ahWarFH6w29';
const MEROSS_URL = 'https://iot.meross.com';
const LOGIN_URL = `${MEROSS_URL}/v1/Auth/Login`;
const LOGOUT_URL = `${MEROSS_URL}/v1/Profile/logout`;
const DEV_LIST = `${MEROSS_URL}/v1/Device/devList`;
const SUBDEV_LIST = `${MEROSS_URL}/v1/Hub/getSubDevices`;

export class MerossCloud extends EventEmitter {
    constructor(options) {
        super();

        this.options = options || {};
        this.token = null;
        this.key = null;
        this.userId = null;
        this.userEmail = null;
        this.authenticated = false;

        this.localHttpFirst = !!options.localHttpFirst;
        this.onlyLocalForGet = this.localHttpFirst ? !!options.onlyLocalForGet : false;

        this.timeout = options.timeout || 10000;

        this.mqttConnections = {};
        this.devices = {};
    }

    async authenticatedPost(url, paramsData) {
        const nonce = generateRandomString(16);
        const timestampMillis = Date.now();
        const loginParams = encodeParams(paramsData);

        // Generate the md5-hash (called signature)
        const datatosign = SECRET + timestampMillis + nonce + loginParams;
        const md5hash = createHash('md5').update(datatosign).digest("hex");
        const headers = {
            "Authorization": `Basic ${this.token || ''}`,
            "vender": "meross",
            "AppVersion": "0.4.4.4",
            "AppType": "MerossIOT",
            "AppLanguage": "EN",
            "User-Agent": "MerossIOT/0.4.4.4"
        };

        const payload = {
            'params': loginParams,
            'sign': md5hash,
            'timestamp': timestampMillis,
            'nonce': nonce
        };

        const options = {
            url: url,
            method: 'POST',
            headers: headers,
            form: payload,
            timeout: this.timeout,
            responseType: 'json',
        };

        this.options.logger &&  this.options.logger(`HTTP-Call: ${JSON.stringify(options)}`);
        // Perform the request.

        const response = await got(url, options)

        if(response.statusCode !== 200 || response.body == null) throw new Error(`HTTP-Response Code: ${response.statusCode}`)
        this.options.logger && this.options.logger('HTTP-Response OK: ' + response.rawBody.toString())

        const { body } = response
        if (body.info !== 'Success') throw new Error(`apiStatus: ${body.apiStatus}: ${body.info}`)
        return body.data
    }

    connectDevice(deviceObj, dev) {
        const deviceId = dev.uuid;
        this.devices[deviceId] = deviceObj;
        this.devices[deviceId].on('connected', () => {
            this.emit('connected', deviceId);
        });
        this.devices[deviceId].on('close', (error) => {
            this.emit('close', deviceId, error);
        });
        this.devices[deviceId].on('error', (error) => {
            if (!this.listenerCount('error')) return;
            this.emit('error', error, deviceId);
        });
        this.devices[deviceId].on('reconnect', () => {
            this.emit('reconnect', deviceId);
        });
        this.devices[deviceId].on('data', (namespace, payload) => {
            this.emit('data', deviceId, namespace, payload);
        });
        this.devices[deviceId].on('rawData', (message) => {
            this.emit('rawData', deviceId, message);
        });
        this.emit('deviceInitialized', deviceId, dev, deviceObj);

        // this.initMqtt(dev);
        deviceObj.connect()
        return deviceObj
    }

    async connect() {
        const data = {
            email: this.options.email,
            password: this.options.password
        }

        const loginResponse = await this.authenticatedPost(LOGIN_URL, data)

        this.token = loginResponse.token
        this.key = loginResponse.key
        this.userId = loginResponse.userid
        this.userEmail = loginResponse.email
        this.authenticated = true

        return await this.getDeviceList()
    }

    async logout() {
        if (!this.authenticated || !this.token) {
            throw(new Error('Not authenticated'));
        }

        return await this.authenticatedPost(LOGOUT_URL, {})
    }

    async getDeviceList () {
        if (this.authenticated === false) throw new Error('Not authenticated yet')
        const deviceList = await this.authenticatedPost(DEV_LIST, {})
        if (deviceList == null || !Array.isArray(deviceList)) throw new Error('Unexpected response from meross servers')
        // promise array of devices
        // this is useful to return either a value or a Promise of a value,
        // in this case the 'value' is a MerossCloudDevice
        const devices = deviceList.map(async (dev) => {
            if (dev.deviceType === 'msh300') {
                this.options.logger && this.options.logger(dev.uuid + ' Detected Hub')

                const subDeviceList = await this.authenticatedPost(SUBDEV_LIST, { uuid: dev.uuid })
                const merossHub = new MerossCloudHubDevice(!this.token, !this.key, !this.userId, dev, subDeviceList)
                return this.connectDevice(merossHub, dev)
            }
            return this.connectDevice(new MerossCloudDevice(!this.token, !this.key, !this.userId, dev), dev)
        })

        return Promise.all(devices)
    }

    getDevice(uuid) {
        return this.devices[uuid];
    }

    disconnectAll(force) {
        for (const deviceId in this.devices) {
            if (!this.devices.hasOwnProperty(deviceId)) continue;
            this.devices[deviceId].disconnect(force);
        }
        for (const domain of Object.keys(this.mqttConnections)) {
            this.mqttConnections[domain].client.end(force);
        }
    }

    initMqtt(dev) {
        const domain = dev.domain || "eu-iot.meross.com"; // reservedDomain ???
        if (!this.mqttConnections[domain] || !this.mqttConnections[domain].client) {
            const appId = createHash('md5').update(`API${uuidv4()}`).digest("hex");
            const clientId = `app:${appId}`;

            // Password is calculated as the MD5 of USERID concatenated with KEY
            const hashedPassword = createHash('md5').update(this.userId + this.key).digest("hex");

            if (!this.mqttConnections[domain]) {
                this.mqttConnections[domain] = {};
            }
            if (this.mqttConnections[domain].client) {
                this.mqttConnections[domain].client.end(true);
            }
            this.mqttConnections[domain].client = mqtt.connect({
                'protocol': 'mqtts',
                'host': domain,
                'port': 2001,
                'clientId': clientId,
                'username': this.userId,
                'password': hashedPassword,
                'rejectUnauthorized': true,
                'keepalive': 30,
                'reconnectPeriod': 5000
            });
            this.mqttConnections[domain].deviceList = this.mqttConnections[domain].deviceList || [];
            if (!this.mqttConnections[domain].deviceList.includes(dev.uuid)) {
                this.mqttConnections[domain].deviceList.push(dev.uuid);
            }

            this.mqttConnections[domain].client.on('connect', () => {
                //console.log("Connected. Subscribe to user topics");

                this.mqttConnections[domain].client.subscribe(`/app/${this.userId}/subscribe`, (err) => {
                    if (err) {
                        this.emit('error', err);
                    }
                    //console.log('User Subscribe Done');
                });

                this.clientResponseTopic = `/app/${this.userId}-${appId}/subscribe`;

                this.mqttConnections[domain].client.subscribe(this.clientResponseTopic, (err) => {
                    if (err) {
                        this.emit('error', err);
                    }
                    //console.log('User Response Subscribe Done');
                });

                this.mqttConnections[domain].deviceList.forEach(devId => {
                    this.devices[devId] && this.devices[devId].emit(this.mqttConnections[domain].silentReInitialization ? 'reconnect' : 'connected');
                });
                this.mqttConnections[domain].silentReInitialization = false;
            });

            this.mqttConnections[domain].client.on('error', (error) => {
                if (error && error.toString().includes('Server unavailable')) {
                    this.mqttConnections[domain].silentReInitialization = true;
                    this.mqttConnections[domain].client.end(true);
                    if (this.mqttConnections[domain].deviceList.length) {
                        setImmediate(() => {
                            this.mqttConnections[domain].client = null;
                            this.initMqtt(this.devices[this.mqttConnections[domain].deviceList[0]]);
                        });
                    }
                }
                this.mqttConnections[domain].deviceList.forEach(devId => {
                    this.devices[devId] && this.devices[devId].emit('error', error ? error.toString() : null);
                });
            });
            this.mqttConnections[domain].client.on('close', (error) => {
                if (this.mqttConnections[domain].silentReInitialization) {
                    return;
                }
                this.mqttConnections[domain].deviceList.forEach(devId => {
                    this.devices[devId] && this.devices[devId].emit('close', error ? error.toString() : null);
                });
            });
            this.mqttConnections[domain].client.on('reconnect', () => {
                this.mqttConnections[domain].deviceList.forEach(devId => {
                    this.devices[devId] && this.devices[devId].emit('reconnect');
                });
            });

            this.mqttConnections[domain].client.on('message', (topic, message) => {
                if (!message) return;
                // message is Buffer
                //console.log(topic + ' <-- ' + message.toString());
                try {
                    message = JSON.parse(message.toString());
                } catch (err) {
                    this.emit('error', `JSON parse error: ${err}`);
                    return;
                }

                if (!message.header.from) return;
                const fromArr = message.header.from.split('/');
                if (this.devices[fromArr[2]]) {
                    this.devices[fromArr[2]].handleMessage(message);
                }
            });

        } else {
            if (!this.mqttConnections[domain].deviceList.includes(dev.uuid)) {
                this.mqttConnections[domain].deviceList.push(dev.uuid);
            }
            if (this.mqttConnections[domain].client.connected) {
                setImmediate(() => {
                    this.devices[dev] && this.devices[dev].emit('connected');
                });
            }
        }
    }

    sendMessageMqtt(dev, data) {
        if (!this.mqttConnections[dev.domain] || ! this.mqttConnections[dev.domain].client) {
            return false;
        }

        this.options.logger &&  this.options.logger(`MQTT-Cloud-Call ${dev.uuid}: ${JSON.stringify(data)}`);
        this.mqttConnections[dev.domain].client.publish(`/appliance/${dev.uuid}/subscribe`, JSON.stringify(data), undefined, err => {
            if (err) {
                this.devices[dev.uuid] && this.devices[dev.uuid].emit('error', err);
            }
        });
        return true;
    }

    sendMessageHttp(dev, ip, payload, callback) {
        const options = {
            url: `http://${ip}/config`,
            method: 'POST',
            json: payload,
            timeout: this.timeout
        };
        this.options.logger &&  this.options.logger(`HTTP-Local-Call ${dev.uuid}: ${JSON.stringify(options)}`);
        // Perform the request.
        request(options, (error, response, body) => {
            if (!error && response && response.statusCode === 200 && body) {
                this.options.logger && this.options.logger(`HTTP-Local-Response OK ${dev.uuid}: ${JSON.stringify(body)}`);
                if (body) {
                    setImmediate(() => {
                        this.devices[dev.uuid].handleMessage(body);
                    })
                    return callback && callback(null);
                }
                return callback && callback(new Error(`${body.apiStatus}: ${body.info}`));
            }
            this.options.logger && this.options.logger(`HTTP-Local-Response Error ${dev.uuid}: ${error} / Status=${response ? response.statusCode : '--'}`);
            return callback && callback(error);
        });
    }

    encodeMessage(method, namespace, payload) {
        const messageId = createHash('md5').update(generateRandomString(16)).digest("hex");
        const timestamp = Math.round(new Date().getTime() / 1000);  //int(round(time.time()))

        const signature = createHash('md5').update(messageId + this.key + timestamp).digest("hex");

        return {
            "header": {
                "from": this.clientResponseTopic,
                "messageId": messageId, // Example: "122e3e47835fefcd8aaf22d13ce21859"
                "method": method, // Example: "GET",
                "namespace": namespace, // Example: "Appliance.System.All",
                "payloadVersion": 1,
                "sign": signature, // Example: "b4236ac6fb399e70c3d61e98fcb68b74",
                "timestamp": timestamp
            },
            "payload": payload
        };
    }

    sendMessage(dev, ip, data, callback) {
        if (this.localHttpFirst && ip) {
            this.sendMessageHttp(dev, ip, data, err => {
                let res = !err;
                const isGetMessage = data && data.header && data.header.method === 'GET';
                let resendToCloud = !isGetMessage || (isGetMessage && !this.onlyLocalForGet);
                if (err && resendToCloud) {
                    res = this.sendMessageMqtt(dev, data);
                }
                callback && callback(res);
            })
        } else {
            callback && callback(this.sendMessageMqtt(dev, data));
        }
    }
}
