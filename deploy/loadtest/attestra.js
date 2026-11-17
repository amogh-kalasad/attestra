// Attestra load test (Phase 8.2, workload classes + SLOs from docs/upgrade/SLO.md, L-03).
// Run only against your own local or staging install, never against a scanned asset:
//   k6 run -e BASE_URL=http://127.0.0.1:8765 -e ENG_ID=1 deploy/loadtest/attestra.js
// A non-local BASE_URL is refused unless ALLOW_REMOTE=1 (staging host you own).
// Needs a user (default: demo lead from `attestra demo`) and the ZAP fixture for imports.
import http from 'k6/http';
import { check, group, sleep } from 'k6';

const BASE = __ENV.BASE_URL || 'http://127.0.0.1:8765';
const ENG = __ENV.ENG_ID || '1';
const USER = __ENV.LT_USER || 'priya.lead';
const PASS = __ENV.LT_PASS || 'demo-lead-pass';
const ZAP = open(__ENV.IMPORT_FILE || '../../tests/fixtures/zap.json');
const VUS = Number(__ENV.VUS || 10);
const DISCOVERY = __ENV.DISCOVERY === '1';

function isLocal(url) {
  return /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?(\/|$)/.test(url);
}

export function setup() {
  if (!isLocal(BASE) && __ENV.ALLOW_REMOTE !== '1') {
    throw new Error(`refusing to load-test ${BASE}: set ALLOW_REMOTE=1 for a staging host you own`);
  }
}

export const options = {
  scenarios: {
    // interactive: login + dashboard + engagement findings (user-facing latency)
    interactive: {
      executor: 'ramping-vus',
      exec: 'interactive',
      startVUs: 0,
      stages: [
        { duration: __ENV.RAMP || '30s', target: VUS },
        { duration: __ENV.HOLD || '2m', target: VUS },
        { duration: '15s', target: 0 },
      ],
    },
    // api-read: JSON reads at a constant arrival rate
    api_read: {
      executor: 'constant-arrival-rate',
      exec: 'apiRead',
      rate: Number(__ENV.READ_RPS || 5),
      timeUnit: '1s',
      duration: __ENV.HOLD || '2m',
      preAllocatedVUs: Math.max(2, Math.ceil(VUS / 2)),
      startTime: __ENV.RAMP || '30s',
    },
    // api-write: imports at a low constant rate (each one creates findings)
    api_write: {
      executor: 'constant-arrival-rate',
      exec: 'apiWrite',
      rate: Number(__ENV.WRITE_PER_MIN || 6),
      timeUnit: '1m',
      duration: __ENV.HOLD || '2m',
      preAllocatedVUs: 2,
      startTime: __ENV.RAMP || '30s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    'http_req_duration{name:login}': ['p(95)<2000'],
    'http_req_duration{name:dashboard}': ['p(95)<2000'],
    'http_req_duration{name:findings}': ['p(95)<1500'],
    'http_req_duration{name:export_sarif}': ['p(95)<3000'],
    'http_req_duration{name:discovery}': ['p(95)<1500'],
    'http_req_duration{name:import}': ['p(95)<5000'],
  },
};

function login() {
  http.cookieJar().clear(BASE);
  const r = http.post(`${BASE}/login`, { username: USER, password: PASS, next: '/' },
    { redirects: 0, tags: { name: 'login' } });
  check(r, { 'login 303': (x) => x.status === 303 });
}

export function interactive() {
  group('login', login);
  group('dashboard', () => {
    const r = http.get(`${BASE}/`, { tags: { name: 'dashboard' } });
    check(r, { 'dashboard 200': (x) => x.status === 200 });
  });
  for (let i = 0; i < 3; i++) {
    const r = http.get(`${BASE}/api/engagements/${ENG}/findings`, { tags: { name: 'findings' } });
    check(r, { 'findings 200': (x) => x.status === 200 });
    sleep(0.5);
  }
  sleep(1);
}

export function apiRead() {
  login();
  const r = http.get(`${BASE}/api/engagements/${ENG}/export/sarif`, { tags: { name: 'export_sarif' } });
  check(r, { 'export 200': (x) => x.status === 200 });
  if (DISCOVERY) {
    const d = http.get(`${BASE}/api/engagements/${ENG}/discovery/candidates`, { tags: { name: 'discovery' } });
    check(d, { 'discovery 200': (x) => x.status === 200 });
  }
}

export function apiWrite() {
  login();
  const r = http.post(`${BASE}/api/engagements/${ENG}/imports`,
    { tool: 'zap', file: http.file(ZAP, 'zap.json', 'application/json') },
    { tags: { name: 'import' } });
  check(r, { 'import 201': (x) => x.status === 201 });
}

// Backwards compatible default (plain `k6 run` without scenarios selection).
export default function () {
  interactive();
}
