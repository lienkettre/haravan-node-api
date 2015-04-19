/**
 * Haravan OAuth2 node.js API
 *
 *
 *
 */
var request = require('request');
var crypto = require('crypto');

function HaravanAPI(config) {

    if (!(this instanceof HaravanAPI)) return new HaravanAPI(config);

    if (config == null) { // == checks for null and undefined
        var msg = "HaravanAPI module expects a config object\n";
        throw new Error(msg);
    }

    this.config = config;

    if (this.config.verbose !== false){
        this.config.verbose = true;
    }

}

HaravanAPI.prototype.buildAuthURL = function(){
    var auth_url = 'https://' + this.config.shop.split(".")[0];
    auth_url += ".myharavan.com/admin/oauth/authorize?";
    auth_url += "client_id=" + this.config.haravan_api_key;
    auth_url += "&scope=" + this.config.haravan_scope;
    auth_url += "&redirect_uri=" + this.config.redirect_uri;
    auth_url += "&response_type=code";
    return auth_url;
};

HaravanAPI.prototype.set_access_token = function(token) {
    this.config.access_token = token;
};

HaravanAPI.prototype.conditional_console_log = function(msg) {
    if (this.config.verbose) {
        console.log( msg );
    }
};

HaravanAPI.prototype.is_valid_signature = function(params) {
    var signature = params['signature'],
        calculated_signature = '';

    var signer = crypto.createHmac('sha256',this.config.haravan_shared_secret);
    if(params['code']) calculated_signature = 'code=' + params['code'];
    calculated_signature += 'shop=' + params['shop'] + 'timestamp=' + params['timestamp'];

    var hash = signer.update(calculated_signature).digest('hex');

    return (hash === signature);
};

HaravanAPI.prototype.exchange_temporary_token = function(query_params, callback) {
    var self = this;
    if (!self.is_valid_signature(query_params)) {
        return callback(new Error("Signature is not authentic!"));
    }
    var options = {
        url: "https://" +  self.hostname() + "/admin/oauth/access_token",
        method: 'POST',
        headers: {
            'Content-Type':     'application/x-www-form-urlencoded'
        },
        form: {
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.haravan_api_key,
            'client_secret': self.config.haravan_shared_secret,
            'code': query_params['code'],
            'grant_type': 'authorization_code'
        }
    };
    request(options, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            try {
                var rs = JSON.parse(body);
                if(rs.access_token){
                    self.set_access_token(rs.access_token);
                    callback(null,rs);
                }else{
                    callback(null);
                }
            } catch(e) {
                callback(e);
            }
        }else{
            callback(error);
        }
    });
};

//get new access_token by refresh_token
HaravanAPI.prototype.refreshAccessToken = function(refresh_token, callback) {
    var self = this;
    var options = {
        url: "https://" + self.hostname() + "/admin/oauth/access_token",
        method: 'POST',
        headers: {
            'Content-Type':     'application/x-www-form-urlencoded'
        },
        form: {
            'client_id': self.config.haravan_api_key,
            'client_secret': self.config.haravan_shared_secret,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }
    }
    request(options, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            try {
                var rs = JSON.parse(body);
                if(rs.access_token){
                    self.set_access_token(rs.access_token);
                    callback(null,rs);
                }else{
                    callback(null);
                }
            } catch(e) {
                callback(e);
            }
        }else{
            callback(error);
        }
    });
};

HaravanAPI.prototype.hostname = function () {
  return this.config.shop.split(".")[0] + '.myharavan.com';
};

HaravanAPI.prototype.port = function () {
  return 443;
};

HaravanAPI.prototype.makeRequest = function(endpoint, method, data, callback, retry) {

    var https = require('https'),
        dataString = JSON.stringify(data),
        options = {
            hostname: this.hostname(),
            path: endpoint,
            method: method.toLowerCase() || 'get',
            port: this.port(),
            headers: {
                'Content-Type': 'application/json'
            }
        },
        self = this;

    if (this.config.access_token) {
      options.headers['Authorization'] = "Bearer " + this.config.access_token;
    }

    if (options.method === 'post' || options.method === 'put' || options.method === 'delete') {
        options.headers['Content-Length'] = new Buffer(dataString).length;
    }

    var request = https.request(options, function(response){
        self.conditional_console_log( 'STATUS: ' + response.statusCode );
        self.conditional_console_log( 'HEADERS: ' + JSON.stringify(response.headers) );

        if (response.headers && response.headers.http_x_haravan_shop_api_call_limit) {
            self.conditional_console_log( 'API_LIMIT: ' + response.headers.http_x_haravan_shop_api_call_limit);
        }

        response.setEncoding('utf8');

        var body = '';

        response.on('data', function(chunk){
            self.conditional_console_log( 'BODY: ' + chunk );
            body += chunk;
        });

        response.on('end', function(){

            var delay = 0;

            // If the request is being rate limited by Haravan, try again after a delay
            if (response.statusCode === 429) {
                return setTimeout(function() {
                    self.makeRequest(endpoint, method, data, callback);
                }, self.config.rate_limit_delay || 10000 );
            }

            // If the backoff limit is reached, add a delay before executing callback function
            if (response.statusCode === 200 && self.has_header(response, 'http_x_haravan_shop_api_call_limit')) {
                var api_limit = parseInt(response.headers['http_x_haravan_shop_api_call_limit'].split('/')[0], 10);
                if (api_limit >= (self.config.backoff || 35)) delay = self.config.backoff_delay || 1000; // in ms
            }

            setTimeout(function(){

                var   json = {}
                    , error;

                try {
                    if (body.trim() != '') { //on some requests, Haravan retuns an empty body (several spaces)
                        json = JSON.parse(body);
                        if (json.hasOwnProperty('error') || json.hasOwnProperty('errors')) {
                            error = {
                                  error : (json.error || json.errors)
                                , code  : response.statusCode
                            };
                        }
                    }
                } catch(e) {
                    error = e;
                }

                callback(error, json, response.headers);
            }, delay); // Delay the callback if we reached the backoff limit

        });

    });

    request.on('error', function(e){
        self.conditional_console_log( "Request Error: ", e );
        if(self.config.retry_errors && !retry){
            var delay = self.config.error_retry_delay || 10000;
            self.conditional_console_log( "retrying once in " + delay + " milliseconds" );
            setTimeout(function() {
                self.makeRequest(endpoint, method, data, callback, true);
            }, delay );
        } else{
            callback(e);
        }
    });

    if (options.method === 'post' || options.method === 'put' || options.method === 'delete') {
        request.write(dataString);
    }

    request.end();

};

HaravanAPI.prototype.get = function(endpoint, data, callback) {
    if (typeof data === 'function' && arguments.length < 3) {
        callback = data;
        data = null;
    }
    this.makeRequest(endpoint,'GET', data, callback);
};

HaravanAPI.prototype.post = function(endpoint, data, callback) {
    this.makeRequest(endpoint,'POST', data, callback);
};

HaravanAPI.prototype.put = function(endpoint, data, callback) {
    this.makeRequest(endpoint, 'PUT', data, callback);
};

HaravanAPI.prototype.delete = function(endpoint, data, callback) {
    if (arguments.length < 3) {
        if (typeof data === 'function') {
            callback = data;
            data = null;
        } else {
            callback = new Function;
            data = typeof data === 'undefined' ? null : data;
        }
    }
    this.makeRequest(endpoint, 'DELETE', data, callback);
};

HaravanAPI.prototype.has_header = function(response, header) {
    return response.headers.hasOwnProperty(header) ? true : false;
};

module.exports = HaravanAPI;
