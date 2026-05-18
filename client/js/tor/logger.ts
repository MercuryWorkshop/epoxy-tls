// Pluggable logger used by the vendored snowflake modules. By default it
// drops everything; the snowflake provider sets this from the user-supplied
// `SnowflakeConfig.log` callback (see `./snowflake.ts`).

export type LogHandler = (msg: string) => void;

let logHandler: LogHandler | null = null;

export function log(msg: string) {
	if (logHandler) logHandler(msg);
}

export function setLogHandler(handler: LogHandler | null) {
	logHandler = handler;
}
