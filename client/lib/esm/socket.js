var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) {
        return value instanceof P ? value : new P(function (resolve) {
            resolve(value);
        });
    }

    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) {
            try {
                step(generator.next(value));
            } catch (e) {
                reject(e);
            }
        }

        function rejected(value) {
            try {
                step(generator["throw"](value));
            } catch (e) {
                reject(e);
            }
        }

        function step(result) {
            result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }

        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = {
        label: 0, sent: function () {
            if (t[0] & 1) throw t[1];
            return t[1];
        }, trys: [], ops: []
    }, f, y, t, g;
    return g = {
        next: verb(0),
        "throw": verb(1),
        "return": verb(2)
    }, typeof Symbol === "function" && (g[Symbol.iterator] = function () {
        return this;
    }), g;

    function verb(n) {
        return function (v) {
            return step([n, v]);
        };
    }

    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0:
                case 1:
                    t = op;
                    break;
                case 4:
                    _.label++;
                    return {value: op[1], done: false};
                case 5:
                    _.label++;
                    y = op[1];
                    op = [0];
                    continue;
                case 7:
                    op = _.ops.pop();
                    _.trys.pop();
                    continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) {
                        _ = 0;
                        continue;
                    }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) {
                        _.label = op[1];
                        break;
                    }
                    if (op[0] === 6 && _.label < t[1]) {
                        _.label = t[1];
                        t = op;
                        break;
                    }
                    if (t && _.label < t[2]) {
                        _.label = t[2];
                        _.ops.push(op);
                        break;
                    }
                    if (t[2]) _.ops.pop();
                    _.trys.pop();
                    continue;
            }
            op = body.call(thisArg, _);
        } catch (e) {
            op = [6, e];
            y = 0;
        } finally {
            f = t = 0;
        }
        if (op[0] & 5) throw op[1];
        return {value: op[0] ? op[1] : void 0, done: true};
    }
};
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
import {useEffect, useMemo, useRef, useState} from "react";
import {createContainer} from "unstated-next";

/** API Endpoint Host */
export var API_ENDPOINT_HOSTNAME = window.location.host;

// makeid is used to generate a random transactionID for the websocket
export function makeid(length) {
    if (length === void 0) {
        length = 12;
    }
    var result = "";
    var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

var DateParse = function () {
    var reISO = /^([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([+|-]([01][0-9]|2[0-3]):[0-5][0-9]))$/;
    return function (_, value) {
        if (typeof value === "string") {
            var a = reISO.exec(value);
            if (a)
                return new Date(value);
        }
        return value;
    };
};
var dp = DateParse();

function protocol() {
    return window.location.protocol.match(/^https/) ? "wss" : "ws";
}

var SocketState;
(function (SocketState) {
    SocketState[SocketState["CONNECTING"] = WebSocket.CONNECTING] = "CONNECTING";
    SocketState[SocketState["OPEN"] = WebSocket.OPEN] = "OPEN";
    SocketState[SocketState["CLOSING"] = WebSocket.CLOSING] = "CLOSING";
    SocketState[SocketState["CLOSED"] = WebSocket.CLOSED] = "CLOSED";
})(SocketState || (SocketState = {}));
var UseWebsocket = function () {
    var _a = useState(SocketState.CLOSED), state = _a[0], setState = _a[1];
    var callbacks = useRef({});
    var onconn = useRef([]);
    var webSocket = useRef(null);
    var send = useRef(function send(key, payload) {
        var transactionID = makeid();
        return new Promise(function (resolve, reject) {
            callbacks.current[transactionID] = function (data) {
                if (data.key === "HUB:ERROR") {
                    reject(data.message);
                    return;
                }
                var result = data.payload;
                resolve(result);
            };
            var sendData = function (ws) {
                // Use network sub menu to see payloads traveling between client and server
                // https://stackoverflow.com/a/5757171
                ws.send(JSON.stringify({
                    key: key,
                    payload: payload,
                    transactionID: transactionID,
                }));
            };
            if (webSocket.current && webSocket.current.readyState === WebSocket.OPEN) {
                sendData(webSocket.current);
            } else {
                // Add to queue (to be run on reconnection)
                onconn.current.push(function (ws) {
                    sendData(ws);
                });
            }
        });
    });
    var subs = useRef({});
    var subscribe = useMemo(function () {
        return function (key, callback) {
            if (subs.current[key])
                subs.current[key].push(callback);
            else
                subs.current[key] = [callback];
            return function () {
                var i = subs.current[key].indexOf(callback);
                if (i === -1)
                    return;
                subs.current[key].splice(i, 1);
            };
        };
    }, []);
    var onReconnect = function () {
        return __awaiter(void 0, void 0, void 0, function () {
            return __generator(this, function (_a) {
                onconn.current.forEach(function (fn) {
                    if (!webSocket.current)
                        throw new Error("no websocket");
                    fn(webSocket.current);
                });
                onconn.current = [];
                return [2 /*return*/];
            });
        });
    };
    var setupWS = useMemo(function () {
        return function (ws, onopen) {
            ;
            window.ws = ws;
            ws.onopen = function () {
                // Use network sub menu to see payloads traveling between client and server
                // https://stackoverflow.com/a/5757171
                // console.info("WebSocket open.")
            };
            ws.onerror = function () {
                // Use network sub menu to see payloads traveling between client and server
                // https://stackoverflow.com/a/5757171
                // console.error("onerror", e)
                ws.close();
            };
            ws.onmessage = function (message) {
                var msgData = JSON.parse(message.data, dp);
                // Use network sub menu to see payloads traveling between client and server
                // https://stackoverflow.com/a/5757171
                if (msgData.key === "WELCOME") {
                    setReadyState();
                    if (onopen) {
                        onopen();
                    }
                }
                if (msgData.transactionID) {
                    var _a = callbacks.current, _b = msgData.transactionID, cb = _a[_b],
                        withoutCb = __rest(_a, [typeof _b === "symbol" ? _b : _b + ""]);
                    if (cb) {
                        cb(msgData);
                        callbacks.current = withoutCb;
                    }
                }
                if (subs.current[msgData.key]) {
                    for (var _i = 0, _c = subs.current[msgData.key]; _i < _c.length; _i++) {
                        var callback = _c[_i];
                        callback(msgData.payload);
                    }
                }
            };
            ws.onclose = function () {
                setReadyState();
            };
        };
    }, []);
    var connect = useMemo(function () {
        return function () {
            return new Promise(function (resolve, _) {
                setState(WebSocket.CONNECTING);
                setTimeout(function () {
                    webSocket.current = new WebSocket("".concat(protocol(), "://").concat(API_ENDPOINT_HOSTNAME, "/api/ws"));
                    setupWS(webSocket.current);
                    resolve(undefined);
                }, 2000);
            });
        };
    }, [setupWS]);
    var setReadyState = function () {
        if (!webSocket.current) {
            setState(WebSocket.CLOSED);
            return;
        }
        setState(webSocket.current.readyState);
    };
    useEffect(function () {
        webSocket.current = new WebSocket("".concat(protocol(), "://").concat(API_ENDPOINT_HOSTNAME, "/api/ws"));
        setupWS(webSocket.current);
        return function () {
            if (webSocket.current)
                webSocket.current.close();
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);
    return {send: send.current, state: state, connect: connect, subscribe: subscribe, onReconnect: onReconnect};
};
var WebsocketContainer = createContainer(UseWebsocket);
export var SocketProvider = WebsocketContainer.Provider;
export var useWebsocket = WebsocketContainer.useContainer;
export default WebsocketContainer;
