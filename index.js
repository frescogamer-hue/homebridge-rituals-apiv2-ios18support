'use strict';

const os = require('os');
const path = require('path');
const store = require('node-storage');
const axios = require('axios');
const qs = require('querystring');

const version = require('./package.json').version;
const author = require('./package.json').author.name;

let Service;
let Characteristic;

module.exports = function(homebridge) {
    Service = homebridge.hap.Service;
    Characteristic = homebridge.hap.Characteristic;
    homebridge.registerAccessory(
        'homebridge-rituals-apiv2-ios18support',
        'Rituals',
        RitualsAccessory
    );
};

function RitualsAccessory(log, config) {
    this.log = log;
    this.services = [];
    this.hub = config.hub || '';
    var dt = Math.floor(Math.random() * 10000) + 1;

    this.cache = {};
    this.cacheTimestamp = {};
    this.cacheDuration = 6 * 1000;

    this.retryCount = 0;
    this.maxRetries = 3;
    this.retryDelay = 10000;

    this.log.debug('RitualsAccessory -> init :: RitualsAccessory(log, config)');

    this.storage = new store(path.join(os.homedir(), '.homebridge') + '/.uix-rituals-secrets_' + this.hub);
    this.user =
        path.join(os.homedir(), '.homebridge') +
        '/.uix-rituals-secrets_' +
        this.hub;
    this.log.debug('RitualsAccessory -> storage path is :: ' + this.user);

    this.on_state;
    this.fan_speed;
    this.account = config.account;
    this.password = config.password;

    this.key = this.storage.get('key') || 0;
    this.log.debug('RitualsAccessory -> key :: ' + this.key);

    this.name = this.storage.get('name') || config.name || 'Genie';
    this.log.debug('RitualsAccessory -> name :: ' + this.name);

    this.hublot = this.storage.get('hublot') || 'SN_RND' + dt;
    this.log.debug('RitualsAccessory -> hublot :: ' + this.hublot);

    this.version = this.storage.get('version') || version;
    this.log.debug('RitualsAccessory -> version :: ' + this.version);

    this.fragance = this.storage.get('fragance') || 'N/A';
    this.log.debug('RitualsAccessory -> fragance :: ' + this.fragance);

    var determinate_model = this.version.split('.');
    if (determinate_model[determinate_model.length - 1] < 12) {
        this.model_version = '1.0';
    } else {
        this.model_version = '2.0';
    }

    // Keep as HumidifierDehumidifier service but simplify to ON/OFF only
    // Bump subtype to ensure HomeKit re-learns characteristics
    this.service = new Service.HumidifierDehumidifier(this.name, 'DiffuserV2');

    // Remove optional / undesired UI characteristics and default humidity
    // Try removing CurrentRelativeHumidity if it exists to hide "Current Humidity"
    const toRemove = [
      Characteristic.RelativeHumidityHumidifierThreshold,
      Characteristic.RelativeHumidityDehumidifierThreshold,
      Characteristic.RotationSpeed,
      Characteristic.SwingMode,
      Characteristic.LockPhysicalControls,
      Characteristic.WaterLevel,
      Characteristic.CurrentRelativeHumidity
    ];
    for (const c of toRemove) {
      try {
        const ch = this.service.getCharacteristic(c);
        this.service.removeCharacteristic(ch);
      } catch (_) {}
    }

    // Only Active and simple state characteristics
    this.service
      .getCharacteristic(Characteristic.Active)
      .on('get', this.getCurrentState.bind(this))
      .on('set', this.setActiveState.bind(this));

    this.service
      .getCharacteristic(Characteristic.CurrentHumidifierDehumidifierState)
      .on('get', (callback) => {
        callback(
          null,
          this.on_state
            ? Characteristic.CurrentHumidifierDehumidifierState.HUMIDIFYING
            : Characteristic.CurrentHumidifierDehumidifierState.INACTIVE
        );
      });

    // Fix TargetHumidifierDehumidifierState to HUMIDIFIER and restrict UI
    const targetChar = this.service.getCharacteristic(Characteristic.TargetHumidifierDehumidifierState);
    targetChar.setProps({
      validValues: [Characteristic.TargetHumidifierDehumidifierState.HUMIDIFIER]
    });
    targetChar
      .on('get', (callback) => {
        callback(null, Characteristic.TargetHumidifierDehumidifierState.HUMIDIFIER);
      })
      .on('set', (value, callback) => {
        setImmediate(() => {
          targetChar.updateValue(Characteristic.TargetHumidifierDehumidifierState.HUMIDIFIER);
          callback();
        });
      });

    // Add WaterLevel to show fill percentage on the main tile
    // (read-only; we update from fill sensor)
    this.waterLevelChar = this.service.addCharacteristic(Characteristic.WaterLevel);
    this.waterLevelChar.setProps({ minValue: 0, maxValue: 100 });
    this.waterLevelChar.on('get', (cb) => {
      const level = typeof this.cache.fill_level === 'number' ? this.cache.fill_level : 0;
      cb(null, level);
    });

    // Also set ConfiguredName to mirror fragrance for better visibility in some Home apps
    try {
      this.configuredNameChar = this.service.getCharacteristic(Characteristic.ConfiguredName)
        || this.service.addCharacteristic(Characteristic.ConfiguredName);
      this._updateConfiguredName();
    } catch (_) {
      // Not all HAP versions support ConfiguredName on this service; ignore if unavailable
    }

    this.serviceInfo = new Service.AccessoryInformation();
    this.serviceInfo
        .setCharacteristic(Characteristic.Manufacturer, author)
        .setCharacteristic(
            Characteristic.Model,
            'Rituals Genie ' + this.model_version
        )
        .setCharacteristic(Characteristic.SerialNumber, this.hublot)
        .setCharacteristic(Characteristic.FirmwareRevision, this.version);

    if (this.model_version == '1.0') {
        this.serviceBatt = new Service.BatteryService('Battery', 'AirFresher');
        this.serviceBatt
            .setCharacteristic(Characteristic.BatteryLevel, '100')
            .setCharacteristic(
                Characteristic.ChargingState,
                Characteristic.ChargingState.CHARGING
            )
            .setCharacteristic(
                Characteristic.StatusLowBattery,
                Characteristic.StatusLowBattery.BATTERY_LEVEL_NORMAL
            )
            .setCharacteristic(Characteristic.Name, 'Genie Battery');
    }

    // Filter service: keep fragrance name and fill % here too
    this.serviceFilter = new Service.FilterMaintenance('Filter', 'AirFresher');
    this.serviceFilter.setCharacteristic(Characteristic.Name, this.fragance);

    this.serviceFilter
        .getCharacteristic(Characteristic.FilterLifeLevel)
        .on('get', this.getFillState.bind(this));

    this.serviceFilter
        .getCharacteristic(Characteristic.FilterChangeIndication)
        .on('get', (callback) => {
            const level = this.cache.fill_level || 100;
            const indication = (level <= 20)
                ? Characteristic.FilterChangeIndication.CHANGE_FILTER
                : Characteristic.FilterChangeIndication.FILTER_OK;
            callback(null, indication);
        });

    this.services.push(this.service);
    this.services.push(this.serviceInfo);
    if (this.serviceBatt) this.services.push(this.serviceBatt);
    this.services.push(this.serviceFilter);

    this.discover();
    this.log.debug('RitualsAccessory -> finish :: RitualsAccessory(log, config)');
}

RitualsAccessory.prototype = {
    _updateConfiguredName: function() {
        try {
            const fragrance = this.cache.fragrance_name || this.fragance || 'Unknown';
            const configured = `${this.name} • ${fragrance}`;
            if (this.configuredNameChar) {
                this.configuredNameChar.updateValue(configured);
            }
        } catch(_) {}
    },

    discover: function () {
        this.log.debug('RitualsAccessory -> init :: discover()');

        const storedToken = this.storage.get('token');
        const storedHub = this.storage.get('hub');
        this.token = storedToken || null;

        if (!storedHub) {
            if (this.hub) {
                this.log.warn('No hub found in storage. Using hub from config (first start): ' + this.hub);
            } else {
                this.log.warn('No hub found in storage. Probably first start.');
            }
        } else {
            this.log.debug(`Hub loaded from storage: ${storedHub}`);
        }

        if (!this.token) {
            this.log.debug('No valid token found – starting authentication…');
            this.authenticateV2AndThen(() => {
                this.getHub();
            });
        } else {
            this.log.debug('Token available – attempting to access hub data');
            this.getHub();
        }

        this.log.debug('RitualsAccessory -> finish :: discover()');
    },

    makeAuthenticatedRequest: function (method, path, data, callback, retry = true) {
        const that = this;
        const token = this.token || this.storage.get('token');

        if (!token) {
            this.log.warn('No valid token available → authenticating…');
            return this.authenticateV2AndThen(() => {
                that.makeAuthenticatedRequest(method, path, data, callback, false);
            });
        }

        const url = 'https://rituals.apiv2.sense-company.com/' + path;

        const headers = {
            'Authorization': token,
            'Accept': '*/*'
        };

        const config = {
            method: method,
            url: url,
            headers: headers,
            timeout: 5000
        };

        if (method === 'post') {
            const bodyStr = typeof data === 'string'
                ? data
                : qs.stringify(data);

            headers['Content-Type'] = 'application/x-www-form-urlencoded';
            config.data = bodyStr;

            that.log.warn('==== REQUEST DUMP =================================');
            that.log.warn('URL     : ' + url);
            that.log.warn('Method  : POST');
            that.log.warn('Headers : ' + JSON.stringify(headers));
            that.log.warn('BodyHex : ' + Buffer.from(bodyStr).toString('hex'));
            that.log.warn('BodyUtf8: ' + bodyStr);
            that.log.warn('===============================================');
        }

        if (method === 'get') {
            that.log.debug(`→ GET ${path}`);
        }

        axios(config).then(response => {
            callback(null, response.data);
        }).catch(error => {
            if (error.response) {
                const res = error.response;

                if (res.status === 401 && retry) {
                    that.log.warn(`401 Unauthorized for ${path} - fetching new token`);
                    that.storage.remove('token');
                    that.token = null;
                    return that.authenticateV2AndThen(() => {
                        that.makeAuthenticatedRequest(method, path, data, callback, false);
                    });
                }

                that.log.warn(`Error ${res.status} in ${method.toUpperCase()} ${path}`);
                that.log.debug('Body:    ' + JSON.stringify(res.data));
                that.log.debug('Headers: ' + JSON.stringify(res.headers));
                return callback(new Error(`HTTP ${res.status} – ${JSON.stringify(res.data)}`));
            } else {
                that.log.warn(`${method.toUpperCase()} ${path} failed: ${error}`);
                return callback(error);
            }
        });
    },

    authenticateV2AndThen: function (next) {
        const that = this;

        if (this.retryCount >= this.maxRetries) {
            this.log.error('Authentication failed after multiple attempts. Aborting..');
            return;
        }

        const url = 'https://rituals.apiv2.sense-company.com/apiv2/account/token';
        const data = {
            email: this.account,
            password: this.password
        };

        axios.post(url, data)
            .then(response => {
                const body = response.data;

                if (!body.success) {
                    throw new Error('No success token received');
                }

                that.token = body.success;
                that.storage.put('token', that.token);
                that.retryCount = 0;

                that.log.debug('Token successfully retrieved: ' + that.token);
                next();
            })
            .catch(err => {
                that.retryCount++;
                const status = err.response?.status || 'no response';
                that.log.warn(`Token retrieval failed (attempt ${that.retryCount}): ${status}`);
                setTimeout(() => that.authenticateV2AndThen(next), that.retryDelay);
            });
    },

    authenticateV2: function () {
        const that = this;

        if (this.retryCount >= this.maxRetries) {
            this.log.error('Authentication failed after multiple attempts. Process aborted.');
            return;
        }

        this.log.debug(`Authentication attempt ${this.retryCount + 1}/${this.maxRetries}`);

        const url = 'https://rituals.apiv2.sense-company.com/apiv2/account/token';
        const data = {
            email: this.account,
            password: this.password
        };

        axios.post(url, data)
            .then(response => {
                const body = response.data;

                if (!body || typeof body.success !== 'string') {
                    const msg = body?.message || 'no success token';
                    that.log.warn(`Authentication denied: ${msg}`);
                    that.log.debug('Server-Body:', JSON.stringify(body));

                    const m = /(\d+)\s+seconds/.exec(msg);
                    if (m) {
                        const wait = parseInt(m[1], 10) * 1000;
                        that.log.info(`Next attempt in ${m[1]} s`);
                        setTimeout(() => that.authenticateV2(), wait);
                    } else {
                        that._scheduleRetry();
                    }
                    return;
                }

                that.token = body.success;
                that.storage.put('token', that.token);
                that.retryCount = 0;
                that.log.debug('New token received:', that.token);
                that.getHub();
            })
            .catch(err => {
                const status = err.response?.status || 'Network error';
                that.log.warn(`Authentication HTTP error: ${status}`);
                if (err.response?.data) that.log.debug('Body:', JSON.stringify(err.response.data));
                that._scheduleRetry();
            });
    },

    _scheduleRetry: function() {
        this.retryCount++;
        setTimeout(() => this.authenticateV2(), this.retryDelay);
    },

    resolveHub: function() {
        const hubFromStorage = this.storage.get('hub');
        const hub = hubFromStorage || this.hub;
        if (!hub) {
            this.log.warn('No hub resolved yet (neither storage nor config). Waiting for discovery...');
        }
        return hub;
    },

    getHub: function () {
        const that = this;
        this.log.debug('RitualsAccessory -> init :: getHub()');

        const now = Date.now();
        if (this.cacheTimestamp.getHub && (now - this.cacheTimestamp.getHub) < this.cacheDuration) {
            that.log.debug('Using cached data for getHub');
            that.applyHubData(this.cache.getHubData);
            return;
        }

        this.makeAuthenticatedRequest('get', 'apiv2/account/hubs', null, function (err, body) {
            if (err) {
                that.log.info(`${that.name} :: ERROR :: apiv2/account/hubs :: getHub() > ${err}`);
                return;
            }

            if (!Array.isArray(body)) {
                that.log.warn('Invalid response structure received, no hubs found.');
                return;
            }

            that.log.debug(`RitualsAccessory -> apiv2/account/hubs OK :: ${body.length} Genies found`);

            that.cache.getHubData = body;
            that.cacheTimestamp.getHub = now;

            that.applyHubData(body);
        });

        this.log.debug('RitualsAccessory -> finish :: getHub()');
    },

    applyHubData: function(body) {
        const that = this;

        if (!Array.isArray(body) || body.length === 0) {
            that.log.warn('No Genies found in the account.');
            return;
        }

        if (body.length === 1) {
            const hub = body[0];
            that.key = 0;
            that.name = hub.attributeValues?.roomnamec || 'Genie';
            that.hublot = hub.hublot;
            that.hub = hub.hash;

            that.storage.put('key', that.key);
            that.storage.put('name', that.name);
            that.storage.put('hublot', that.hublot);
            that.storage.put('hub', that.hub);

            that.fragance = 'Unknown';
            that.storage.put('fragance', that.fragance);

            that.log.debug('RitualsAccessory -> hub 1 genie updated');
        } else {
            let found = false;

            Object.keys(body).forEach(function(key) {
                const hub = body[key];
                if (hub.hash === that.hub) {
                    found = true;
                    that.key = key;
                    that.name = hub.attributeValues?.roomnamec || 'Genie';
                    that.hublot = hub.hublot;
                    that.fragance = 'Unknown';

                    that.hub = hub.hash;
                    that.storage.put('hub', that.hub);

                    that.storage.put('key', key);
                    that.storage.put('name', that.name);
                    that.storage.put('hublot', that.hublot);
                    that.storage.put('fragance', that.fragance);

                    that.log.debug('RitualsAccessory -> HUB matched and preferences stored');
                }
            });

            if (!found) {
                that.log.info('************************************************');
                that.log.info('HUB in Config NOT validated or missing.');
                that.log.info('Multiple Genies found, select correct one in config.json.');
                that.log.info('************************************************');
                Object.keys(body).forEach(function(key) {
                    const hub = body[key];
                    that.log.info('********************');
                    that.log.info('Name   : ' + (hub.attributeValues?.roomnamec || 'Unknown'));
                    that.log.info('Hublot : ' + hub.hublot);
                    that.log.info('Hub    : ' + hub.hash);
                    that.log.info('Key    : ' + key);
                });
                that.log.info('************************************************');
            }
        }
    },

    getCurrentState: function(callback) {
        const that = this;
        this.log.debug('RitualsAccessory -> init :: getCurrentState()');

        const now = Date.now();
        if (this.cacheTimestamp.getCurrentState && (now - this.cacheTimestamp.getCurrentState) < this.cacheDuration) {
            that.log.debug('Using cached data for getCurrentState');
            callback(null, this.cache.on_state);
            return;
        }

        const hub = that.resolveHub();
        if (!hub) {
            return callback(new Error('Hub not resolved yet'));
        }
        that.log.debug(`Retrieving the current status for hub: ${hub}`);

        that.makeAuthenticatedRequest('get', `apiv2/hubs/${hub}/attributes/fanc`, null, function(err1, fancRes) {
            if (err1) {
                that.log.debug(`Error while retrieving fanc: ${err1}`);
                return callback(err1);
            }

            that.log.debug(`fancRes received: ${JSON.stringify(fancRes)}`);

            that.on_state = fancRes.value === '1';
            that.cache.on_state = that.on_state;
            that.cacheTimestamp.getCurrentState = now;

            that.log.debug(`Current status -> on_state: ${that.on_state}`);

            callback(null, that.on_state);
        });

        this.log.debug('RitualsAccessory -> finish :: getCurrentState()');
    },

    getFillState: function(callback) {
        const that = this;
        this.log.debug('RitualsAccessory -> init :: getFillState()');

        const now = Date.now();
        if (this.cacheTimestamp.getFillState && (now - this.cacheTimestamp.getFillState) < this.cacheDuration) {
            that.log.debug('Using cached data for getFillState');

            if (this.cache.fragrance_name) {
                this.serviceFilter.updateCharacteristic(Characteristic.Name, this.cache.fragrance_name);
                this._updateConfiguredName();
            }
            // Update WaterLevel on main service
            if (typeof this.cache.fill_level === 'number' && this.waterLevelChar) {
                this.waterLevelChar.updateValue(this.cache.fill_level);
            }

            return callback(null, this.cache.fill_level);
        }

        const hub = that.resolveHub();
        if (!hub) {
            return callback(new Error('Hub not resolved yet'));
        }
        that.log.debug(`Retrieving fill level for hub: ${hub}`);

        that.makeAuthenticatedRequest('get', `apiv2/hubs/${hub}/sensors/fillc`, null, function(err, fillRes) {
            if (err) {
                that.log.debug(`Error while retrieving fillc: ${err}`);
                return callback(err);
            }

            that.log.debug(`fillRes received: ${JSON.stringify(fillRes)}`);

            let fillPercent = 0;
            if (fillRes && fillRes.title) {
                const match = fillRes.title.match(/(\d+)-(\d+)%/);
                if (match) {
                    const low = parseInt(match[1], 10);
                    const high = parseInt(match[2], 10);
                    fillPercent = Math.round((low + high) / 2);
                } else {
                    const singleMatch = fillRes.title.match(/(\d+)%/);
                    if (singleMatch) {
                        fillPercent = parseInt(singleMatch[1], 10);
                    }
                }
            }

            if (fillPercent < 0 || fillPercent > 100) {
                fillPercent = 0;
            }

            that.cache.fill_level = fillPercent;
            that.cacheTimestamp.getFillState = now;

            that.log.debug(`Current fill level -> ${fillPercent}%`);

            // Mirror fill into WaterLevel on the main service
            try {
                if (that.waterLevelChar) that.waterLevelChar.updateValue(fillPercent);
            } catch(_) {}

            // Get fragrance and mirror into Filter service Name and main service configured name
            that.makeAuthenticatedRequest('get', `apiv2/hubs/${hub}/sensors/rfidc`, null, function(err2, fragRes) {
                if (!err2 && fragRes && fragRes.title) {
                    const fragranceName = fragRes.title;
                    that.cache.fragrance_name = fragranceName;
                    that.log.debug(`Current fragrance note -> ${fragranceName}`);

                    try {
                        that.serviceFilter.updateCharacteristic(Characteristic.Name, fragranceName);
                    } catch(_) {}

                    that._updateConfiguredName();
                } else if (err2) {
                    that.log.debug(`Error while retrieving rfidc: ${err2}`);
                }

                callback(null, fillPercent);
            });
        });

        this.log.debug('RitualsAccessory -> finish :: getFillState()');
    },

    setActiveState: function(active, callback) {
        const that = this;
        const hub = that.resolveHub();
        if (!hub) {
            return callback(new Error('Hub not resolved yet'), this.on_state);
        }
        const setValue = active ? '1' : '0';

        const path = `apiv2/hubs/${hub}/attributes/fanc`;
        const body = qs.stringify({ fanc: setValue });

        this.log.info(`${that.name} :: Set ActiveState to => ${setValue}`);
        this.log.debug(`POST URL: ${path}`);
        this.log.debug(`POST Body (x-www-form-urlencoded): ${body}`);

        this.makeAuthenticatedRequest('post', path, body, function(err, response) {
            if (err) {
                that.log.warn(`Set ActiveState failed with error: ${err.message}`);
                return callback(err, that.on_state);
            }

            that.log.debug(`Response from server: ${JSON.stringify(response)}`);

            that.on_state = active;
            that.cache.on_state = active;
            that.cacheTimestamp.getCurrentState = Date.now();

            callback();
        });
    },

    identify: function(callback) {
        callback();
    },

    getServices: function() {
        return this.services;
    },
};
