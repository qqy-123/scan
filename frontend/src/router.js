import { createRouter, createWebHistory } from 'vue-router'
import DashboardView from './views/DashboardView.vue'
import ProjectsView from './views/ProjectsView.vue'
import ProjectDetailView from './views/ProjectDetailView.vue'
import ResultDetailView from './views/ResultDetailView.vue'
import FingerprintsView from './views/FingerprintsView.vue'
import SettingsView from './views/SettingsView.vue'

export default createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'dashboard', component: DashboardView },
    {
      path: '/projects',
      name: 'projects',
      component: ProjectsView,
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
  ],
})
