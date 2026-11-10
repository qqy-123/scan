import axios from 'axios'

const api = axios.create({ baseURL: '/', timeout: 60000 })

api.interceptors.request.use((cfg) => {
  const t = localStorage.getItem('scan_token')
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  return cfg
})

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401 && location.pathname !== '/login') {
      localStorage.removeItem('scan_token')
      location.href = '/login?next=' + encodeURIComponent(location.pathname)
    }
    return Promise.reject(err)
  },
)

export default {
  login: (password) => api.post('/api/login', { password }),
  overview: () => api.get('/api/overview'),
  listProjects: () => api.get('/api/projects'),
  createProject: (data) => api.post('/api/projects', data),
  updateProject: (id, data) => api.put(`/api/projects/${id}`, data),
  deleteProject: (id) => api.delete(`/api/projects/${id}`),
  getProject: (id) => api.get(`/api/projects/${id}`),
  addTargets: (pid, urls) =>
    api.post(`/api/projects/${pid}/targets`, { urls }),
  uploadTargets: (pid, file) => {
    const fd = new FormData()
    fd.append('file', file)
    return api.post(`/api/projects/${pid}/targets/upload`, fd)
  },
  deleteTarget: (tid) => api.delete(`/api/targets/${tid}`),
  updateTarget: (tid, url) => api.put(`/api/targets/${tid}`, { url }),
  createScan: (pid, opts) => api.post(`/api/projects/${pid}/scans`, opts),
  getScan: (sid) => api.get(`/api/scans/${sid}`),
  scanStats: (sid) => api.get(`/api/scans/${sid}/stats`),
  getResult: (rid) => api.get(`/api/results/${rid}`),
  rules: () => api.get('/api/rules'),
  rulesDetail: () => api.get('/api/rules/detail'),
  ruleRaw: (name) => api.get(`/api/rules/raw/${encodeURIComponent(name)}`),
  updateRule: (rule) => api.put('/api/rules/custom', { rule }),
  setRuleDisabled: (name, disabled) =>
    api.post(`/api/rules/${encodeURIComponent(name)}/${disabled ? 'disable' : 'enable'}`),
  learnPreview: (url) => api.post('/api/learn/preview', { url }),
  saveCustomRule: (data) => api.post('/api/rules/custom', data),
  deleteCustomRule: (name) =>
    api.delete(`/api/rules/custom/${encodeURIComponent(name)}`),
  getSettings: () => api.get('/api/settings'),
  updateSettings: (data) => api.put('/api/settings', data),
  systemInfo: () => api.get('/api/system'),
  createExposure: (pid, opts) => api.post(`/api/projects/${pid}/exposure`, opts),
  listExposure: (pid) => api.get(`/api/projects/${pid}/exposure`),
  listExposureAll: () => api.get('/api/exposure'),
  exposureStats: () => api.get('/api/exposure/stats'),
  getExposure: (rid) => api.get(`/api/exposure/${rid}`),
  deepScanExposure: (rid, limit = 120) => api.post(`/api/exposure/${rid}/deepscan`, { limit }),
  deleteExposure: (rid) => api.delete(`/api/exposure/${rid}`),
  exposureDiff: (rid) => api.get(`/api/exposure/${rid}/diff`),
  exposureRowResponse: (id) => api.get(`/api/exposure/result/${id}/response`),
  exportExposure: (rid, fmt = 'csv') =>
    api.get(`/api/exposure/${rid}/export?fmt=${fmt}`, { responseType: 'blob' }),
}
