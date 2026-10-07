/**
 * Wire protocol types — TypeScript mirror of
 * `apps/api/src/omniagent/sandboxes/browser/models.py`.
 *
 * Keep the two in sync (SPEC §6 wants a generated file from
 * `packages/protocol/*.schema.json`; until then this is the hand-maintained
 * mirror and the Python module is the source of truth).
 */

/* -------------------------------------------------------------------------- */
/* Identity & authorization                                                    */
/* -------------------------------------------------------------------------- */

export const ROLES = ['VIEWER', 'OPERATOR', 'ADMIN'] as const;
export type Role = (typeof ROLES)[number];

export type Permission =
  | 'screen:view'
  | 'input:send'
  | 'takeover:control'
  | 'graph:manage'
  | 'audit:read';

/** What a VIEWER may do: watch the stream, nothing else. */
export const VIEWER_PERMISSIONS: readonly Permission[] = ['screen:view'];
export const OPERATOR_PERMISSIONS: readonly Permission[] = [
  'screen:view',
  'input:send',
  'takeover:control',
];

export function can(permissions: readonly Permission[], permission: Permission): boolean {
  return permissions.includes(permission);
}

/* -------------------------------------------------------------------------- */
/* Message types                                                               */
/* -------------------------------------------------------------------------- */

export const ClientMessageType = {
  MOUSE_EVENT: 'MOUSE_EVENT',
  KEYBOARD_EVENT: 'KEYBOARD_EVENT',
  SET_TAKEOVER: 'SET_TAKEOVER',
  PING: 'PING',
  AUTH: 'AUTH',
} as const;
export type ClientMessageTypeValue =
  (typeof ClientMessageType)[keyof typeof ClientMessageType];

export const ServerMessageType = {
  SCREEN_FRAME: 'SCREEN_FRAME',
  STREAM_READY: 'STREAM_READY',
  STREAM_RECONNECTING: 'STREAM_RECONNECTING',
  STREAM_ERROR: 'STREAM_ERROR',
  TAKEOVER_STATE: 'TAKEOVER_STATE',
  SESSION_READY: 'SESSION_READY',
  AUTH_REQUIRED: 'AUTH_REQUIRED',
  RATE_LIMITED: 'RATE_LIMITED',
  PONG: 'PONG',
  ERROR: 'ERROR',
} as const;
export type ServerMessageTypeValue =
  (typeof ServerMessageType)[keyof typeof ServerMessageType];

/** Application error codes (mirror of `AppErrorCode`). */
export const AppErrorCode = {
  INVALID_PAYLOAD: 40001,
  VALIDATION_FAILED: 40002,
  UNKNOWN_MESSAGE_TYPE: 40003,
  UNAUTHENTICATED: 40100,
  TOKEN_EXPIRED: 40101,
  TOKEN_INVALID: 40102,
  TOKEN_REPLAYED: 40103,
  FORBIDDEN: 40300,
  TAKEOVER_NOT_ACTIVE: 40301,
  GRAPH_FORBIDDEN: 40302,
  TAKEOVER_LEASE_CONFLICT: 40303,
  SESSION_NOT_READY: 40901,
  MESSAGE_TOO_LARGE: 41301,
  RATE_LIMITED: 42901,
  CONNECTION_LIMIT: 42902,
  INTERNAL: 50000,
  CDP_DISPATCH_FAILED: 50201,
  CDP_DISPATCH_TIMEOUT: 50401,
} as const;
export type AppErrorCodeValue = (typeof AppErrorCode)[keyof typeof AppErrorCode];

/** WebSocket close codes (mirror of `WsCloseCode`). */
export const WsCloseCode = {
  NORMAL: 1000,
  GOING_AWAY: 1001,
  POLICY_VIOLATION: 1008,
  BAD_REQUEST: 4400,
  UNAUTHORIZED: 4401,
  FORBIDDEN: 4403,
  IDLE_TIMEOUT: 4408,
  PAYLOAD_TOO_LARGE: 4413,
  TOO_MANY_REQUESTS: 4429,
  INTERNAL_ERROR: 4500,
  STREAM_ENDED: 4501,
  SERVICE_UNAVAILABLE: 4503,
} as const;

/** Close codes that mean "re-authenticating will not help — stop retrying". */
export const TERMINAL_CLOSE_CODES: readonly number[] = [
  WsCloseCode.FORBIDDEN,
  WsCloseCode.PAYLOAD_TOO_LARGE,
];

/* -------------------------------------------------------------------------- */
/* Envelopes                                                                   */
/* -------------------------------------------------------------------------- */

export type ScreenFrame = {
  type: typeof ServerMessageType.SCREEN_FRAME;
  seq: number;
  format: 'jpeg' | 'png';
  width: number;
  height: number;
  data_b64: string;
  device_width: number;
  device_height: number;
  page_scale_factor: number;
};

export type StreamReady = {
  type: typeof ServerMessageType.STREAM_READY;
  graph_id: string;
  page_url: string;
  format: 'jpeg' | 'png';
  quality: number | null;
  max_width: number;
  max_height: number;
};

export type StreamReconnecting = {
  type: typeof ServerMessageType.STREAM_RECONNECTING;
  graph_id: string;
  attempt: number;
  delay_s: number;
  reason: string;
};

export type StreamError = {
  type: typeof ServerMessageType.STREAM_ERROR;
  graph_id: string;
  fatal?: boolean;
  message: string;
};

export type SessionReady = {
  type: typeof ServerMessageType.SESSION_READY;
  graph_id: string;
  connection_id: string;
  subject: string;
  role: Role;
  permissions: Permission[];
  credential_expires_at: number | null;
  refreshed?: boolean;
  rate_limits: {
    input: { capacity: number; per_second: number };
    control: { capacity: number; per_second: number };
    message: { capacity: number; per_second: number };
    mouse_move_coalesce_ms: number;
  };
  takeover: {
    requires_role: Role;
    input_requires_takeover: boolean;
    single_holder: boolean;
    lease_ttl_s: number;
    max_lease_s: number;
  };
  limits: {
    idle_timeout_s: number;
    max_lifetime_s: number;
    max_message_bytes: number;
  };
};

export type TakeoverState = {
  type: typeof ServerMessageType.TAKEOVER_STATE;
  graph_id: string;
  enabled: boolean;
  reason?: string;
  holder?: string | null;
  connection_id?: string;
  acquired_at?: number;
  expires_at?: number;
  lease_expires_at?: number | null;
  lease_ms?: number;
};

export type AuthRequired = {
  type: typeof ServerMessageType.AUTH_REQUIRED;
  reason: 'credential_expiring' | 'credential_expired' | string;
  expires_in_s: number;
  grace_s: number;
};

export type RateLimited = {
  type: typeof ServerMessageType.RATE_LIMITED;
  limit: string;
  retry_after_ms: number;
  strikes?: number;
};

export type ErrorEnvelope = {
  type: typeof ServerMessageType.ERROR;
  code: AppErrorCodeValue | number;
  message: string;
  limit?: string;
  retry_after_ms?: number;
  required_role?: Role;
  required_permission?: Permission;
  action?: string;
  holder_is_other?: boolean;
};

export type Pong = {
  type: typeof ServerMessageType.PONG;
  ts_ms: number;
  echo?: unknown;
};

export type ServerEnvelope =
  | ScreenFrame
  | StreamReady
  | StreamReconnecting
  | StreamError
  | SessionReady
  | TakeoverState
  | AuthRequired
  | RateLimited
  | ErrorEnvelope
  | Pong;

/* -------------------------------------------------------------------------- */
/* Client -> server payloads                                                   */
/* -------------------------------------------------------------------------- */

export type MouseAction = 'move' | 'down' | 'up' | 'click' | 'double_click' | 'wheel';
export type MouseButton = 'left' | 'right' | 'middle' | 'none';
export type KeyAction = 'keydown' | 'keyup' | 'keypress' | 'insert_text';
export type ModifierKey = 'alt' | 'ctrl' | 'control' | 'meta' | 'command' | 'shift';

export type MousePayload = {
  action: MouseAction;
  x?: number;
  y?: number;
  button?: MouseButton;
  clickCount?: number;
  buttons?: number;
  deltaX?: number;
  deltaY?: number;
  modifiers?: ModifierKey[];
};

export type KeyboardPayload = {
  action: KeyAction;
  key?: string;
  code?: string;
  text?: string;
  autoRepeat?: boolean;
  location?: 0 | 1 | 2 | 3;
  modifiers?: ModifierKey[];
};

export type ClientEnvelope =
  | { type: typeof ClientMessageType.MOUSE_EVENT; payload: MousePayload }
  | { type: typeof ClientMessageType.KEYBOARD_EVENT; payload: KeyboardPayload }
  | {
      type: typeof ClientMessageType.SET_TAKEOVER;
      payload: { enabled: boolean; leaseMs?: number; reason?: string };
    }
  | { type: typeof ClientMessageType.PING; payload?: { ts?: number } }
  | { type: typeof ClientMessageType.AUTH; payload: { token: string } };
