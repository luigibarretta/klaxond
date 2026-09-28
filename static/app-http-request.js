import { apiFetch } from "./app.js";

export const J = async (url, opts) => {
  const response = await apiFetch(url, opts);
  if (!response.ok) {
    const detail = (await response.text()).trim().slice(0, 500);
    throw new Error(`${response.status} ${detail || response.statusText}`);
  }
  const contentType = response.headers.get("content-type") || "";
  return contentType.includes("json") ? response.json() : response.text();
};
