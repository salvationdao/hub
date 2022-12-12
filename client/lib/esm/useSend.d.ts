/// <reference types="react" />
export declare const useQuery: <P = any, R = any>(hubKey: string, initFetch?: boolean | undefined, request?: R | undefined) => {
    loading: boolean;
    payload: P | undefined;
    error: string | undefined;
    query: (request?: R | undefined) => Promise<P | undefined>;
    setPayload: import("react").Dispatch<import("react").SetStateAction<P | undefined>>;
};
