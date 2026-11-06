import axios from 'axios'

const api = axios.create({ baseURL: '/', timeout: 60000 })

export default {
  listProjects: () => api.get('/api/projects'),
  createProject: (data) => api.post('/api/projects', data),
  getProject: (id) => api.get(`/api/projects/${id}`),
  addTargets: (pid, urls) =>
    api.post(`/api/projects/${pid}/targets`, { urls }),
  uploadTargets: (pid, file) => {
    const fd = new FormData()
    fd.append('file', file)
    return api.post(`/api/projects/${pid}/targets/upload`, fd)
  },
  deleteTarget: (tid) => api.delete(`/api/targets/${tid}`),
  createScan: (pid, opts) => api.post(`/api/projects/${pid}/scans`, opts),
  getScan: (sid) => api.get(`/api/scans/${sid}`),
  scanStats: (sid) => api.get(`/api/scans/${sid}/stats`),
  getResult: (rid) => api.get(`/api/results/${rid}`),
  rules: () => api.get('/api/rules'),
  rulesDetail: () => api.get('/api/rules/detail'),
  learnPreview: (url) => api.post('/api/learn/preview', { url }),
  saveCustomRule: (data) => api.post('/api/rules/custom', data),
  deleteCustomRule: (name) =>
    api.delete(`/api/rules/custom/${encodeURIComponent(name)}`),
}
