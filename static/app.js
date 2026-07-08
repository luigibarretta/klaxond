// Stable facade for feature modules. Keep imports from "./app.js" working while
// the runtime implementation lives in focused ESM modules.

export * from "./app-core.js";
export * from "./app-http.js";
export * from "./app-query.js";
export * from "./app-routing-core.js";
export * from "./app-toast.js";
