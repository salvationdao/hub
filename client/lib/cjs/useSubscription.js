"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var react_1 = require("react");
var socket_1 = require("./socket");
function useSubscription(key) {
    var subscribe = (0, socket_1.useWebsocket)().subscribe;
    var _a = (0, react_1.useState)(), payload = _a[0], setPayload = _a[1];
    (0, react_1.useEffect)(function () {
        return subscribe(key, function (payload) {
            setPayload(payload);
        });
    }, [key, subscribe]);
    return payload;
}
exports.default = useSubscription;
