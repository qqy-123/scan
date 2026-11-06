import axios from 'axios'

const api = axios.create({ baseURL: '/', timeout: 60000 })

export default {
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
}
