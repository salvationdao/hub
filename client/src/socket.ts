import {useEffect, useMemo, useRef, useState} from "react"
import {createContainer} from "unstated-next"

/** API Endpoint Host */
export const API_ENDPOINT_HOSTNAME = window.location.host

// makeid is used to generate a random transactionID for the websocket
export function makeid(length: number = 12): string {
    let result = ""
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length))
    }
    return result
}

const DateParse = () => {
    const reISO =
        /^([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([+|-]([01][0-9]|2[0-3]):[0-5][0-9]))$/

    return function (_: string, value: any) {
        if (typeof value === "string") {
            const a = reISO.exec(value)
            if (a) return new Date(value)
        }
        return value
    }
}

const dp = DateParse()

function protocol() {
    return window.location.protocol.match(/^https/) ? "wss" : "ws"
}

enum SocketState {
    CONNECTING = WebSocket.CONNECTING,
    OPEN = WebSocket.OPEN,
    CLOSING = WebSocket.CLOSING,
    CLOSED = WebSocket.CLOSED,
}

type WSSendFn = <Y = any, X = any>(key: string, payload?: X) => Promise<Y>

interface WebSocketProperties {
    send: WSSendFn
    connect: () => Promise<undefined>
    state: SocketState
    subscribe: <T>(key: string, callback: (payload: T) => void) => () => void
    onReconnect: () => Promise<void>
}

type SubscribeCallback = (payload: any) => void

export interface Message<T> {
    transactionID?: string
    key: string
    payload: T
}

type WSCallback<T = any> = (data: T) => void

interface HubError {
    transactionID: string
    key: string
    message: string
}

const UseWebsocket = (): WebSocketProperties => {
    const [state, setState] = useState<SocketState>(SocketState.CLOSED)
    const callbacks = useRef<{ [key: string]: WSCallback }>({})
    const onconn = useRef<((ws: WebSocket) => void)[]>([])

    const webSocket = useRef<WebSocket | null>(null)

    const send = useRef<WSSendFn>(function send<Y = any, X = any>(key: string, payload?: X): Promise<Y> {
        const transactionID = makeid()

        return new Promise(function (resolve, reject) {
            callbacks.current[transactionID] = (data: Message<Y> | HubError) => {
                if (data.key === "HUB:ERROR") {
                    reject((data as HubError).message)
                    return
                }
                const result = (data as Message<Y>).payload
                resolve(result)
            }

            const sendData = (ws: WebSocket) => {
                // Use network sub menu to see payloads traveling between client and server
                // https://stackoverflow.com/a/5757171
                ws.send(
                    JSON.stringify({
                        key,
                        payload,
                        transactionID,
                    }),
                )
            }

            if (webSocket.current && webSocket.current.readyState === WebSocket.OPEN) {
                sendData(webSocket.current)
            } else {
                // Add to queue (to be run on reconnection)
                onconn.current.push((ws: WebSocket) => {
                    sendData(ws)
                })
            }
        })
    })

    const subs = useRef<{ [key: string]: SubscribeCallback[] }>({})

    const subscribe = useMemo(() => {
        return <T>(key: string, callback: (payload: T) => void) => {
            if (subs.current[key]) subs.current[key].push(callback)
            else subs.current[key] = [callback]

            return () => {
                const i = subs.current[key].indexOf(callback)
                if (i === -1) return
                subs.current[key].splice(i, 1)
            }
        }
    }, [])

    const onReconnect = async () => {
        onconn.current.forEach((fn) => {
            if (!webSocket.current) throw new Error("no websocket")
            fn(webSocket.current)
        })
        onconn.current = []
    }

    const setupWS = useMemo(
        () => (ws: WebSocket, onopen?: () => void) => {
            ;(window as any).ws = ws

            ws.onopen = () => {
                // Use network sub menu to see payloads traveling between client and server
                // https://stackoverflow.com/a/5757171
                // console.info("WebSocket open.")
            }
            ws.onerror = () => {
                // Use network sub menu to see payloads traveling between client and server
                // https://stackoverflow.com/a/5757171
                // console.error("onerror", e)
                ws.close()
            }
            ws.onmessage = (message) => {
                const msgData = JSON.parse(message.data, dp)
                // Use network sub menu to see payloads traveling between client and server
                // https://stackoverflow.com/a/5757171

                if (msgData.key === "WELCOME") {
                    setReadyState()
                    if (onopen) {
                        onopen()
                    }
                }
                if (msgData.transactionID) {
                    const {[msgData.transactionID]: cb, ...withoutCb} = callbacks.current
                    if (cb) {
                        cb(msgData)
                        callbacks.current = withoutCb
                    }
                }
                if (subs.current[msgData.key]) {
                    for (const callback of subs.current[msgData.key]) {
                        callback(msgData.payload)
                    }
                }
            }
            ws.onclose = () => {
                setReadyState()
            }
        },
        [],
    )

    const connect = useMemo(() => {
        return (): Promise<undefined> => {
            return new Promise(function (resolve, _) {
                setState(WebSocket.CONNECTING)
                setTimeout(() => {
                    webSocket.current = new WebSocket(`${protocol()}://${API_ENDPOINT_HOSTNAME}/api/ws`)
                    setupWS(webSocket.current)
                    resolve(undefined)
                }, 2000)
            })
        }
    }, [setupWS])

    const setReadyState = () => {
        if (!webSocket.current) {
            setState(WebSocket.CLOSED)
            return
        }
        setState(webSocket.current.readyState)
    }

    useEffect(() => {
        webSocket.current = new WebSocket(`${protocol()}://${API_ENDPOINT_HOSTNAME}/api/ws`)
        setupWS(webSocket.current)

        return () => {
            if (webSocket.current) webSocket.current.close()
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    return {send: send.current, state, connect, subscribe, onReconnect}
}

const WebsocketContainer = createContainer(UseWebsocket)
export const SocketProvider = WebsocketContainer.Provider
export const useWebsocket = WebsocketContainer.useContainer

export default WebsocketContainer
