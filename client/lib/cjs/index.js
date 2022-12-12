"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.useSubscription = exports.useQuery = exports.useWebsocket = exports.SocketProvider = exports.WebsocketContainer = void 0;
var socket_1 = require("./socket");
Object.defineProperty(exports, "SocketProvider", { enumerable: true, get: function () { return socket_1.SocketProvider; } });
Object.defineProperty(exports, "useWebsocket", { enumerable: true, get: function () { return socket_1.useWebsocket; } });
var useSend_1 = require("./useSend");
Object.defineProperty(exports, "useQuery", { enumerable: true, get: function () { return useSend_1.useQuery; } });
var useSubscription_1 = __importDefault(require("./useSubscription"));
exports.useSubscription = useSubscription_1.default;
var socket_2 = __importDefault(require("./socket"));
exports.WebsocketContainer = socket_2.default;
