import { useEffect, useState } from "react";

export default function usePolling(fetcher, interval = 2000, deps = []) {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        let mounted = true;

        async function run() {
            try {
                const result = await fetcher();
                if (mounted) {
                    setData(result);
                    setError(null);
                }
            } catch (err) {
                if (mounted) setError(err);
            } finally {
                if (mounted) setLoading(false);
            }
        }

        run();
        const timer = setInterval(run, interval);

        return () => {
            mounted = false;
            clearInterval(timer);
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [interval, ...deps]);

    return { data, loading, error, setData };
}
