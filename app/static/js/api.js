export class ApiError extends Error {
  constructor(status, detail) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

export async function api(path, { method = "GET", body } = {}) {
  try {
    const res = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: body !== undefined ? { "Content-Type": "application/json" } : {},
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    let parsed = null;
    if (res.status !== 204) {
      const text = await res.text();
      if (text) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = text;
        }
      }
    }

    if (!res.ok) {
      let detail;
      if (parsed && typeof parsed === "object" && typeof parsed.detail === "string") {
        detail = parsed.detail;
      } else if (parsed && typeof parsed === "object" && parsed.detail !== undefined) {
        detail = JSON.stringify(parsed.detail);
      } else {
        detail = res.statusText;
      }

      if (res.status === 401) {
        document.dispatchEvent(new CustomEvent("netlens:unauth"));
      }

      throw new ApiError(res.status, detail);
    }

    return parsed;
  } catch (err) {
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(0, "network error");
  }
}

export const get = (p) => api(p);
export const post = (p, body = {}) => api(p, { method: "POST", body });
export const put = (p, body) => api(p, { method: "PUT", body });
export const patch = (p, body) => api(p, { method: "PATCH", body });
export const del = (p) => api(p, { method: "DELETE" });