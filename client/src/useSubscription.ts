import { useEffect, useState } from "react"
import { useWebsocket } from "./socket"

function useSubscription<T>(key: string): T | undefined {
	const { subscribe } = useWebsocket()

	const [payload, setPayload] = useState<T>()

	useEffect(() => {
		return subscribe<T>(key, (payload: T) => {
			setPayload(payload)
		})
	}, [key, subscribe])

	return payload
}

export default useSubscription
