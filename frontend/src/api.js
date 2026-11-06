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
}
