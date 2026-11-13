/* API client — same endpoints as the old Vue frontend. */

export class ApiError extends Error {
  status: number;
  constructor(status: number, msg: string) {
    super(msg);
    this.status = status;
  }
}

async function req<T = any>(
  method: string,
  url: string,
  body?: unknown,
  form?: FormData,
): Promise<T> {
  const headers: Record<string, string> = {};
  const t =
    typeof window !== "undefined" ? localStorage.getItem("scan_token") : null;
  if (t) headers.Authorization = `Bearer ${t}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const r = await fetch(url, {
    method,
    headers,
    body: form ?? (body !== undefined ? JSON.stringify(body) : undefined),
  });
  if (r.status === 401) {
    if (typeof window !== "undefined") {
      localStorage.removeItem("scan_token");
      if (!location.pathname.startsWith("/login"))
        location.href =
          "/login/?next=" + encodeURIComponent(location.pathname + location.search);
    }
    throw new ApiError(401, "unauthorized");
  }
  if (!r.ok) {
    let msg = `${r.status}`;
    try {
      msg = (await r.json()).detail || msg;
    } catch {}
    throw new ApiError(r.status, msg);
  }
  const ct = r.headers.get("content-type") || "";
  return (ct.includes("json") ? r.json() : r.blob()) as Promise<T>;
}

const get = <T = any>(u: string) => req<T>("GET", u);
const post = <T = any>(u: string, b?: unknown) => req<T>("POST", u, b);
const put = <T = any>(u: string, b?: unknown) => req<T>("PUT", u, b);
const del = <T = any>(u: string) => req<T>("DELETE", u);

export const api = {
  login: (password: string) => post("/api/login", { password }),
  overview: () => get("/api/overview"),
  listProjects: () => get("/api/projects"),
  createProject: (data: any) => post("/api/projects", data),
  updateProject: (id: number, data: any) => put(`/api/projects/${id}`, data),
  deleteProject: (id: number) => del(`/api/projects/${id}`),
  getProject: (id: number) => get(`/api/projects/${id}`),
  addTargets: (pid: number, urls: string[]) =>
    post(`/api/projects/${pid}/targets`, { urls }),
  uploadTargets: (pid: number, file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return req("POST", `/api/projects/${pid}/targets/upload`, undefined, fd);
  },
  listImports: (pid: number) => get(`/api/projects/${pid}/imports`),
  deleteTarget: (tid: number) => del(`/api/targets/${tid}`),
  batchDeleteTargets: (ids: number[]) =>
    post("/api/targets/batch-delete", { ids }),
  updateTarget: (tid: number, url: string) =>
    put(`/api/targets/${tid}`, { url }),
  createScan: (pid: number, opts: any) => post(`/api/projects/${pid}/scans`, opts),
  getScan: (sid: number) => get(`/api/scans/${sid}`),
  scanStats: (sid: number) => get(`/api/scans/${sid}/stats`),
  getResult: (rid: number) => get(`/api/results/${rid}`),
  rules: () => get("/api/rules"),
  rulesDetail: () => get("/api/rules/detail"),
  ruleRaw: (name: string) => get(`/api/rules/raw/${encodeURIComponent(name)}`),
  updateRule: (rule: any) => put("/api/rules/custom", { rule }),
  setRuleDisabled: (name: string, disabled: boolean) =>
    post(`/api/rules/${encodeURIComponent(name)}/${disabled ? "disable" : "enable"}`),
  learnPreview: (url: string) => post("/api/learn/preview", { url }),
  saveCustomRule: (data: any) => post("/api/rules/custom", data),
  deleteCustomRule: (name: string) =>
    del(`/api/rules/custom/${encodeURIComponent(name)}`),
  getSettings: () => get("/api/settings"),
  updateSettings: (data: any) => put("/api/settings", data),
  systemInfo: () => get("/api/system"),
  createExposure: (pid: number, opts: any) =>
    post(`/api/projects/${pid}/exposure`, opts),
  targetExposure: (tid: number) => get(`/api/targets/${tid}/exposure`),
  listExposure: (pid: number) => get(`/api/projects/${pid}/exposure`),
  listExposureAll: () => get("/api/exposure"),
  exposureStats: () => get("/api/exposure/stats"),
  getExposure: (rid: number) => get(`/api/exposure/${rid}`),
  deepScanExposure: (rid: number, limit = 120) =>
    post(`/api/exposure/${rid}/deepscan`, { limit }),
  deleteExposure: (rid: number) => del(`/api/exposure/${rid}`),
  exposureDiff: (rid: number) => get(`/api/exposure/${rid}/diff`),
  exposureRowResponse: (id: number) => get(`/api/exposure/result/${id}/response`),
  exportExposure: (rid: number, fmt = "csv") =>
    req<Blob>("GET", `/api/exposure/${rid}/export?fmt=${fmt}`),
};
