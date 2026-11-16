import type { LiveEvent } from "@/api/types";
import type { ConnectionStatus } from "@/store/live";

export const PING_MS = 20_000;
const FIRST_RETRY_MS = 1_000;
const LONGEST_RETRY_MS = 30_000;

/** Waits double each time, up to 30 s, with up to 20% jitter so many tabs don't retry in step. */
export function retryDelay(attempt: number, random: () => number = Math.random): number {
  const base = Math.min(LONGEST_RETRY_MS, FIRST_RETRY_MS * 2 ** attempt);
  return Math.round(base * (1 + 0.2 * random()));
}

interface StreamMessage {
  type: string;
  data?: unknown;
}

function isEvent(value: unknown): value is LiveEvent {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { id?: unknown }).id === "string" &&
    typeof (value as { type?: unknown }).type === "string"
  );
}

export interface StreamOptions {
  url: string;
  /** Events created after `afterId`: what was missed while disconnected. Any order. */
  fetchMissed: (afterId: string) => Promise<LiveEvent[]>;
  onEvents: (events: LiveEvent[]) => void;
  onStatus: (status: ConnectionStatus) => void;
  lastEventId: () => string | null;
  createSocket?: (url: string) => WebSocket;
  random?: () => number;
}

/**
 * The dashboard's live connection. It reconnects with backoff and, after a reconnect, fetches
 * the events it missed, so the feed has no silent gaps.
 */
export class LiveStream {
  private socket: WebSocket | null = null;
  private attempt = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private closed = false;

  constructor(private readonly options: StreamOptions) {}

  connect(): void {
    this.closed = false;
    const create = this.options.createSocket ?? ((url: string) => new WebSocket(url));
    const socket = create(this.options.url);
    this.socket = socket;
    socket.onopen = () => this.handleOpen();
    socket.onmessage = (message: MessageEvent) => this.handleMessage(message.data);
    socket.onclose = () => this.handleClose();
    socket.onerror = () => socket.close();
  }

  close(): void {
    this.closed = true;
    this.clearTimers();
    this.socket?.close();
    this.socket = null;
  }

  private handleOpen(): void {
    this.attempt = 0;
    this.options.onStatus("live");
    this.pingTimer = setInterval(() => this.send({ type: "ping" }), PING_MS);
    const lastId = this.options.lastEventId();
    if (lastId !== null) void this.catchUp(lastId);
  }

  private async catchUp(lastId: string): Promise<void> {
    try {
      this.options.onEvents(await this.options.fetchMissed(lastId));
    } catch {
      // The live stream still works. The gap shows up as missing history, not a broken page.
    }
  }

  private handleMessage(raw: unknown): void {
    if (typeof raw !== "string") return;
    let message: StreamMessage;
    try {
      message = JSON.parse(raw) as StreamMessage;
    } catch {
      return;
    }
    if (message.type === "event" && isEvent(message.data)) {
      this.options.onEvents([message.data]);
    }
  }

  private handleClose(): void {
    this.clearTimers();
    this.socket = null;
    if (this.closed) return;
    this.options.onStatus("reconnecting");
    const delay = retryDelay(this.attempt, this.options.random);
    this.attempt += 1;
    this.retryTimer = setTimeout(() => this.connect(), delay);
  }

  private send(message: StreamMessage): void {
    if (this.socket?.readyState === WebSocket.OPEN) this.socket.send(JSON.stringify(message));
  }

  private clearTimers(): void {
    if (this.retryTimer !== null) clearTimeout(this.retryTimer);
    if (this.pingTimer !== null) clearInterval(this.pingTimer);
    this.retryTimer = null;
    this.pingTimer = null;
  }
}
