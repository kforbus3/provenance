// Provenance load smoke test.
//
// Exercises the hot read paths (auth + inventory + audit) under modest
// concurrency. Run against a stack seeded with a known user:
//
//   k6 run -e BASE=http://localhost:8080 \
//          -e USER=admin -e PASS='Sup3r-Secret-Pass!' \
//          deploy/load/k6-smoke.js
//
// Tune virtual users / duration via the `options` block or CLI flags.

import http from "k6/http";
import { check, sleep } from "k6";

const BASE = __ENV.BASE || "http://localhost:8080";
const USER = __ENV.USER || "admin";
const PASS = __ENV.PASS || "Sup3r-Secret-Pass!";

export const options = {
  scenarios: {
    read_paths: {
      executor: "ramping-vus",
      startVUs: 1,
      stages: [
        { duration: "15s", target: 20 },
        { duration: "30s", target: 20 },
        { duration: "15s", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.02"], // <2% errors
    http_req_duration: ["p(95)<800"], // 95% under 800ms
  },
};

function login() {
  const res = http.post(`${BASE}/api/v1/auth/login`, JSON.stringify({ username: USER, password: PASS }), {
    headers: { "Content-Type": "application/json" },
  });
  check(res, { "login 200": (r) => r.status === 200 });
  try {
    return JSON.parse(res.body).accessToken;
  } catch {
    return null;
  }
}

export default function () {
  const token = login();
  if (!token) {
    sleep(1);
    return;
  }
  const authHeaders = { headers: { Authorization: `Bearer ${token}` } };

  const me = http.get(`${BASE}/api/v1/auth/me`, authHeaders);
  check(me, { "me 200": (r) => r.status === 200 });

  const hosts = http.get(`${BASE}/api/v1/hosts`, authHeaders);
  check(hosts, { "hosts 200": (r) => r.status === 200 });

  const audit = http.get(`${BASE}/api/v1/audit?limit=20`, authHeaders);
  check(audit, { "audit 200": (r) => r.status === 200 });

  const health = http.get(`${BASE}/health`);
  check(health, { "health 200": (r) => r.status === 200 });

  sleep(1);
}
