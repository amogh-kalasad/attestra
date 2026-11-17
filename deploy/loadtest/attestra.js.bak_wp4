// Attestra load test (Phase 8.2). Run only against your own local or staging install.
//   k6 run -e BASE_URL=http://127.0.0.1:8765 -e ENG_ID=1 deploy/loadtest/attestra.js
// Needs a user (default: demo lead from `attestra demo`) and the ZAP fixture for imports.
import http from 'k6/http';
import { check, group, sleep } from 'k6';

const BASE = __ENV.BASE_URL || 'http://127.0.0.1:8765';
const ENG = __ENV.ENG_ID || '1';
const USER = __ENV.LT_USER || 'priya.lead';
const PASS = __ENV.LT_PASS || 'demo-lead-pass';
const ZAP = open(__ENV.IMPORT_FILE || '../../tests/fixtures/zap.json');

export const options = {
  scenarios: {
    browse: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: __ENV.RAMP || '30s', target: Number(__ENV.VUS || 10) },
        { duration: __ENV.HOLD || '2m', target: Number(__ENV.VUS || 10) },
        { duration: '15s', target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    'http_req_duration{name:login}': ['p(95)<2000'],
    'http_req_duration{name:dashboard}': ['p(95)<2000'],
    'http_req_duration{name:findings}': ['p(95)<1500'],
    'http_req_duration{name:import}': ['p(95)<5000'],
    'http_req_duration{name:export_sarif}': ['p(95)<3000'],
  },
};

export default function () {
  // Each iteration logs in fresh so login is measured under load.
  http.cookieJar().clear(BASE);
  group('login', () => {
    const r = http.post(`${BASE}/login`, { username: USER, password: PASS, next: '/' },
      { redirects: 0, tags: { name: 'login' } });
    check(r, { 'login 303': (x) => x.status === 303 });
  });
  group('dashboard', () => {
    const r = http.get(`${BASE}/`, { tags: { name: 'dashboard' } });
    check(r, { 'dashboard 200': (x) => x.status === 200 });
  });
  for (let i = 0; i < 3; i++) {
    const r = http.get(`${BASE}/api/engagements/${ENG}/findings`, { tags: { name: 'findings' } });
    check(r, { 'findings 200': (x) => x.status === 200 });
    sleep(0.5);
  }
  if (Math.random() < 0.2) {
    group('import', () => {
      const r = http.post(`${BASE}/api/engagements/${ENG}/imports`,
        { tool: 'zap', file: http.file(ZAP, 'zap.json', 'application/json') },
        { tags: { name: 'import' } });
      check(r, { 'import 201': (x) => x.status === 201 });
    });
  }
  group('export', () => {
    const r = http.get(`${BASE}/api/engagements/${ENG}/export/sarif`, { tags: { name: 'export_sarif' } });
    check(r, { 'export 200': (x) => x.status === 200 });
  });
  sleep(1);
}
