import { useCallback, useEffect, useState } from "react"
import { useWebsocket } from "./socket"

export const useQuery = <P = any, R = any>(hubKey: string, initFetch?: boolean, request?: R) => {
	const { send } = useWebsocket()
	const [loading, setLoading] = useState<boolean>(false)
	const [payload, setPayload] = useState<P | undefined>(undefined)
	const [error, setError] = useState<string | undefined>(undefined)
	const [initFetched, setInitFetched] = useState(false)

	const query = useCallback(
		async (request?: R) => {
			setLoading(true)
			try {
				const rsp = await send<P, R>(hubKey, request)
				setError(undefined)
				setPayload(rsp)
				return rsp
			} catch (e) {
				setError(typeof e === "string" ? e : "Something went wrong, please try again.")
			} finally {
				setLoading(false)
			}
			return undefined
		},
		[hubKey, send],
	)
	useEffect(() => {
		if (initFetch !== true || initFetched) return
		setInitFetched(true)
		query(request)
	}, [query, initFetch, request, initFetched])

	return { loading, payload, error, query, setPayload }
}
