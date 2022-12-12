import { useEffect, useState } from "react";
import { useWebsocket } from "./socket";
function useSubscription(key) {
    var subscribe = useWebsocket().subscribe;
    var _a = useState(), payload = _a[0], setPayload = _a[1];
    useEffect(function () {
        return subscribe(key, function (payload) {
            setPayload(payload);
        });
    }, [key, subscribe]);
    return payload;
}
export default useSubscription;
