import { logMessage } from "./api";

function format(...args: unknown[]): string {
  return args
    .map((a) => (typeof a === "string" ? a : JSON.stringify(a)))
    .join(" ");
}

/** Thin wrapper: logs to browser console AND to the Rust log file (fire-and-forget). */
export const log = {
  debug(...args: unknown[]) {
    console.debug(...args);
    logMessage("debug", format(...args)).catch(() => {});
  },
  info(...args: unknown[]) {
    console.info(...args);
    logMessage("info", format(...args)).catch(() => {});
  },
  warn(...args: unknown[]) {
    console.warn(...args);
    logMessage("warn", format(...args)).catch(() => {});
  },
  error(...args: unknown[]) {
    console.error(...args);
    logMessage("error", format(...args)).catch(() => {});
  },
};
