import { createRouter, createWebHistory } from 'vue-router'
import DashboardView from './views/DashboardView.vue'
import ProjectsView from './views/ProjectsView.vue'
import ProjectDetailView from './views/ProjectDetailView.vue'
import ResultDetailView from './views/ResultDetailView.vue'
import FingerprintsView from './views/FingerprintsView.vue'
import SettingsView from './views/SettingsView.vue'
import LoginView from './views/LoginView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: LoginView },
    { path: '/', name: 'dashboard', component: DashboardView },
    {
      path: '/projects',
      name: 'projects',
      component: ProjectsView,
    },
    {
      path: '/projects/:pid/scans/:sid',
      name: 'scan-results',
      component: () => import('./views/ScanResultsView.vue'),
    },
    {
      path: '/projects/:id',
      name: 'project',
      component: ProjectDetailView,
      props: true,
    },
    {
      path: '/results/:id',
      name: 'result',
      component: ResultDetailView,
      props: true,
    },
    {
      path: '/fingerprints',
      name: 'fingerprints',
      component: FingerprintsView,
    },
    {
      path: '/exposure',
      name: 'exposure',
      component: () => import('./views/ExposureView.vue'),
    },
    {
      path: '/settings',
      name: 'settings',
      component: SettingsView,
    },
    {
      path: '/:pathMatch(.*)*',
      name: 'not-found',
      component: () => import('./views/NotFoundView.vue'),
    },
  ],
})

router.beforeEach((to) => {
  if (to.name !== 'login' && !localStorage.getItem('scan_token')) {
    return { name: 'login', query: { next: to.fullPath } }
  }
  if (to.name === 'login' && localStorage.getItem('scan_token')) {
    return { name: 'dashboard' }
  }
})

export default router
