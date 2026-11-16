import { useEffect } from "react";

import { fetchEventsAfter, fetchRecentEvents } from "@/api/client";
import { LiveStream } from "@/lib/stream";
import { useLiveStore } from "@/store/live";

function streamUrl(): string {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${window.location.host}/v1/stream`;
}

/** Opens the live stream once for the whole app, after loading recent history. */
export function useLiveStream(): void {
  useEffect(() => {
    const store = useLiveStore.getState();
    const stream = new LiveStream({
      url: streamUrl(),
      fetchMissed: fetchEventsAfter,
      onEvents: store.addEvents,
      onStatus: store.setStatus,
      lastEventId: () => useLiveStore.getState().lastEventId,
    });
    fetchRecentEvents()
      .then(store.addEvents)
      .catch(() => {
        // The API may not be up yet. The stream retries and the banner says so.
      });
    stream.connect();
    return () => stream.close();
  }, []);
}
