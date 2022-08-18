import { EventEmitter } from 'events'

export class MerossCloudDevice extends EventEmitter {

    constructor(cloudInstance, dev) {
        super();

        this.clientResponseTopic = null;
        this.waitingMessageIds = {};

        this.dev = dev;
        this.cloudInst = cloudInstance;

        this.deviceConnected = false;
    }

    handleMessage(message) {
        if (!this.deviceConnected) return;
        if (!message || !message.header) return;
        if (message && message.header && message.header.from && !message.header.from.includes(this.dev.uuid)) return;
        // {"header":{"messageId":"14b4951d0627ea904dd8685c480b7b2e","namespace":"Appliance.Control.ToggleX","method":"PUSH","payloadVersion":1,"from":"/appliance/1806299596727829081434298f15a991/publish","timestamp":1539602435,"timestampMs":427,"sign":"f33bb034ac2d5d39289e6fa3dcead081"},"payload":{"togglex":[{"channel":0,"onoff":0,"lmTime":1539602434},{"channel":1,"onoff":0,"lmTime":1539602434},{"channel":2,"onoff":0,"lmTime":1539602434},{"channel":3,"onoff":0,"lmTime":1539602434},{"channel":4,"onoff":0,"lmTime":1539602434}]}}

        // If the message is the RESP for some previous action, process return the control to the "stopped" method.
        if (this.waitingMessageIds[message.header.messageId]) {
            if (this.waitingMessageIds[message.header.messageId].timeout) {
                clearTimeout(this.waitingMessageIds[message.header.messageId].timeout);
            }
            this.waitingMessageIds[message.header.messageId].callback(null, message.payload || message);
            delete this.waitingMessageIds[message.header.messageId];
        }
        else if (message.header.method === "PUSH") { // Otherwise process it accordingly
            const namespace = message.header ? message.header.namespace : '';
            this.emit('data', namespace, message.payload || message);
        }
        this.emit('rawData', message);
    }

    /**
     * @deprecated
     */
    connect() {
        this.deviceConnected = true;
    }

    /**
     * @deprecated
     */
    disconnect() {
        this.deviceConnected = false;
    }

    setKnownLocalIp(ip) {
        this.knownLocalIp = ip;
    }

    removeKnownLocalIp() {
        this.knownLocalIp = '';
    }

    publishMessage(method, namespace, payload, callback) {
        const data = this.cloudInst.encodeMessage(method, namespace, payload);
        const messageId = data.header.messageId;
        this.cloudInst.sendMessage(this.dev, this.knownLocalIp, data, res => {
            if (!res) {
                return callback && callback(new Error('Device has no data connection available'));
            }
            if (callback) {
                this.waitingMessageIds[messageId] = {};
                this.waitingMessageIds[messageId].callback = callback;
                this.waitingMessageIds[messageId].timeout = setTimeout(() => {
                    //console.log('TIMEOUT');
                    if (this.waitingMessageIds[messageId].callback) {
                        this.waitingMessageIds[messageId].callback(new Error('Timeout'));
                    }
                    delete this.waitingMessageIds[messageId];
                }, this.cloudInst.timeout * 2);
            }
            this.emit('rawSendData', data);
        });
        return messageId;
    }

    getSystemAllData(callback) {
        // {"all":{"system":{"hardware":{"type":"mss425e","subType":"eu","version":"2.0.0","chipType":"mt7682","uuid":"1806299596727829081434298f15a991","macAddress":"34:29:8f:15:a9:91"},"firmware":{"version":"2.1.2","compileTime":"2018/08/13 10:42:53 GMT +08:00","wifiMac":"34:31:c4:73:3c:7f","innerIp":"192.168.178.86","server":"iot.meross.com","port":2001,"userId":64416},"time":{"timestamp":1539612975,"timezone":"Europe/Berlin","timeRule":[[1521939600,7200,1],[1540688400,3600,0],[1553994000,7200,1],[1572138000,3600,0],[1585443600,7200,1],[1603587600,3600,0],[1616893200,7200,1],[1635642000,3600,0],[1648342800,7200,1],[1667091600,3600,0],[1679792400,7200,1],[1698541200,3600,0],[1711846800,7200,1],[1729990800,3600,0],[1743296400,7200,1],[1761440400,3600,0],[1774746000,7200,1],[1792890000,3600,0],[1806195600,7200,1],[1824944400,3600,0]]},"online":{"status":1}},"digest":{"togglex":[{"channel":0,"onoff":0,"lmTime":1539608841},{"channel":1,"onoff":0,"lmTime":1539608841},{"channel":2,"onoff":0,"lmTime":1539608841},{"channel":3,"onoff":0,"lmTime":1539608841},{"channel":4,"onoff":0,"lmTime":1539608841}],"triggerx":[],"timerx":[]}}}

        return this.publishMessage("GET", "Appliance.System.All", {}, callback);
    }

    getSystemDebug(callback) {
        // {"debug":{"system":{"version":"2.1.2","sysUpTime":"114h16m34s","localTimeOffset":7200,"localTime":"Mon Oct 15 16:23:03 2018","suncalc":"7:42;19:49"},"network":{"linkStatus":"connected","signal":50,"ssid":"ApollonHome","gatewayMac":"34:31:c4:73:3c:7f","innerIp":"192.168.178.86","wifiDisconnectCount":1},"cloud":{"activeServer":"iot.meross.com","mainServer":"iot.meross.com","mainPort":2001,"secondServer":"smart.meross.com","secondPort":2001,"userId":64416,"sysConnectTime":"Mon Oct 15 08:06:40 2018","sysOnlineTime":"6h16m23s","sysDisconnectCount":5,"pingTrace":[]}}}
        return this.publishMessage("GET", "Appliance.System.Debug", {}, callback);
    }

    getSystemAbilities(callback) {
        // {"payloadVersion":1,"ability":{"Appliance.Config.Key":{},"Appliance.Config.WifiList":{},"Appliance.Config.Wifi":{},"Appliance.Config.Trace":{},"Appliance.System.All":{},"Appliance.System.Hardware":{},"Appliance.System.Firmware":{},"Appliance.System.Debug":{},"Appliance.System.Online":{},"Appliance.System.Time":{},"Appliance.System.Ability":{},"Appliance.System.Runtime":{},"Appliance.System.Report":{},"Appliance.System.Position":{},"Appliance.System.DNDMode":{},"Appliance.Control.Multiple":{"maxCmdNum":5},"Appliance.Control.ToggleX":{},"Appliance.Control.TimerX":{"sunOffsetSupport":1},"Appliance.Control.TriggerX":{},"Appliance.Control.Bind":{},"Appliance.Control.Unbind":{},"Appliance.Control.Upgrade":{},"Appliance.Digest.TriggerX":{},"Appliance.Digest.TimerX":{}}}
        return this.publishMessage("GET", "Appliance.System.Ability", {}, callback);
    }

    getSystemReport(callback) {
        return this.publishMessage("GET", "Appliance.System.Report", {}, callback);
    }

    getSystemRuntime(callback) { // Wifi Strength
        // "payload": {
        // 		"runtime": {
        // 			"signal": 86
        // 		}
        // 	}
        return this.publishMessage("GET", "Appliance.System.Runtime", {}, callback);
    }

    getSystemDNDMode(callback) { // DND Mode (LED)
        // "payload": {
        // 		"DNDMode": {
        // 			"mode": 0
        // 		}
        // 	}
        return this.publishMessage("GET", "Appliance.System.DNDMode", {}, callback);
    }

    setSystemDNDMode(onoff, callback) {
        const payload = {"DNDMode": {"mode": onoff ? 1 : 0}};
        return this.publishMessage("SET", "Appliance.System.DNDMode", payload, callback);
    }


    getOnlineStatus(callback) {
        return this.publishMessage("GET", "Appliance.System.Online", {}, callback);
    }

    getConfigWifiList(callback) {
        // {"wifiList":[]}
        return this.publishMessage("GET", "Appliance.Config.WifiList", {}, callback);
    }

    getConfigTrace(callback) {
        // {"trace":{"ssid":"","code":0,"info":""}}
        return this.publishMessage("GET", "Appliance.Config.Trace", {}, callback);
    }

    getControlPowerConsumption(callback) {
        return this.publishMessage("GET", "Appliance.Control.Consumption", {}, callback);
    }

    getControlPowerConsumptionX(callback) {
        return this.publishMessage("GET", "Appliance.Control.ConsumptionX", {}, callback);
    }

    getControlElectricity(callback) {
        return this.publishMessage("GET", "Appliance.Control.Electricity", {}, callback);
    }

    controlToggle(onoff, callback) {
        const payload = {"toggle": {"onoff": onoff ? 1 : 0}};
        return this.publishMessage("SET", "Appliance.Control.Toggle", payload, callback);
    }

    controlToggleX(channel, onoff, callback) {
        const payload = {"togglex": {"channel": channel, "onoff": onoff ? 1 : 0}};
        return this.publishMessage("SET", "Appliance.Control.ToggleX", payload, callback);
    }

    controlSpray(channel, mode, callback) {
        const payload = {"spray": {"channel": channel, "mode": mode || 0}};
        return this.publishMessage("SET", "Appliance.Control.Spray", payload, callback);
    }

    controlRollerShutterUp(channel, callback) {
        const payload = {"position": {"position": 100, "channel": channel}};
        return this.publishMessage("SET", "Appliance.RollerShutter.Position", payload, callback);
    }

    controlRollerShutterDown(channel, callback) {
        const payload = {"position": {"position": 0, "channel": channel}};
        return this.publishMessage("SET", "Appliance.RollerShutter.Position", payload, callback);
    }

    controlRollerShutterStop(channel, callback) {
        const payload = {"position": {"position": -1, "channel": channel}};
        return this.publishMessage("SET", "Appliance.RollerShutter.Position", payload, callback);
    }

    getRollerShutterState(callback) {
        return this.publishMessage("GET", "Appliance.RollerShutter.State", {}, callback);
    }

    getRollerShutterPosition(callback) {
        return this.publishMessage("GET", "Appliance.RollerShutter.Position", {}, callback);
    }

    controlGarageDoor(channel, open, callback) {
        const payload = {"state": {"channel": channel, "open": open ? 1 : 0, "uuid": this.dev.uuid}};
        return this.publishMessage("SET", "Appliance.GarageDoor.State", payload, callback);
    }

    // {"light":{"capacity":6,"channel":0,"rgb":289,"temperature":80,"luminance":100}}
    controlLight(light, callback) {
        const payload = {"light": light};
        return this.publishMessage("SET", "Appliance.Control.Light", payload, callback);
    }

    controlDiffusorSpray(type, channel, mode, callback) {
        const payload = {"spray": [{"channel": channel, "mode": mode || 0, "uuid": this.dev.uuid}]};
        return this.publishMessage("SET", "Appliance.Control.Diffuser.Spray", payload, callback);
    }

    controlDiffusorLight(type, light, callback) {
        light.uuid = this.dev.uuid;
        const payload = {"light": [light]};
        return this.publishMessage("SET", "Appliance.Control.Diffuser.Light", payload, callback);
    }

    controlThermostatMode(channel, modeData, callback) {
        modeData.channel = channel;
        const payload = {"mode": [modeData]};
        return this.publishMessage("SET", "Appliance.Control.Thermostat.Mode", payload, callback);
    }

}
