/// <reference types="react" />
/** API Endpoint Host */
export declare const API_ENDPOINT_HOSTNAME: string;

export declare function makeid(length?: number): string;

declare enum SocketState {
    CONNECTING,
    OPEN,
    CLOSING,
    CLOSED
}

declare type WSSendFn = <Y = any, X = any>(key: string, payload?: X) => Promise<Y>;

interface WebSocketProperties {
    send: WSSendFn;
    connect: () => Promise<undefined>;
    state: SocketState;
    subscribe: <T>(key: string, callback: (payload: T) => void) => () => void;
    onReconnect: () => Promise<void>;
}

export interface Message<T> {
    transactionID?: string;
    key: string;
    payload: T;
}

declare const WebsocketContainer: import("unstated-next").Container<WebSocketProperties, void>;
export declare const SocketProvider: import("react").ComponentType<import("unstated-next").ContainerProviderProps<void>>;
export declare const useWebsocket: () => WebSocketProperties;
export default WebsocketContainer;
