import { createRouter, createWebHistory } from 'vue-router'
import ProjectsView from './views/ProjectsView.vue'
import ProjectDetailView from './views/ProjectDetailView.vue'
import ResultDetailView from './views/ResultDetailView.vue'
import FingerprintsView from './views/FingerprintsView.vue'

export default createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'projects', component: ProjectsView },
    {
      path: '/fingerprints',
      name: 'fingerprints',
      component: FingerprintsView,
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
  ],
})
