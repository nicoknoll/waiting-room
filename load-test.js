/**
 * k6 load test for waitingroom
 *
 * Install: brew install k6
 * Run (local docker-compose):  k6 run load-test.js
 * Run (against prod):           k6 run -e BASE_URL=https://your-domain.com load-test.js
 *
 * Scenarios:
 *   1. thundering_herd  — everyone arrives at once (pre-sale open)
 *   2. steady_queue     — queue is full, users refreshing periodically
 *
 * Metrics to watch:
 *   - http_req_duration p(95) and p(99)
 *   - waiting_room_granted  (counter: how many got access)
 *   - waiting_room_queued   (counter: how many ended up in queue)
 *   - waiting_room_errors   (counter: Redis errors / 500s)
 */

import http from "k6/http";
import { check, sleep } from "k6";

import { Counter, Trend } from "k6/metrics";
import { randomIntBetween } from "https://jslib.k6.io/k6-utils/1.4.0/index.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const BASE_URL = __ENV.BASE_URL || "http://localhost:8888";
const PROTECTED_PATH = __ENV.PROTECTED_PATH || "/kdp/";

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const grantedCounter = new Counter("waiting_room_granted");
const queuedCounter = new Counter("waiting_room_queued");
const errorCounter = new Counter("waiting_room_errors");
const promotionLatency = new Trend("waiting_room_promotion_latency_ms");

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

export const options = {
  // Persist cookies across iterations so each VU = one user, not one user per iteration
  noCookiesReset: true,
  scenarios: {
    // Scenario 1: Everyone shows up at once (the actual pre-sale moment).
    // With MAX_USERS=50, the first 50 should be granted immediately,
    // the rest queued. No one should see a 500.
    thundering_herd: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "5s", target: 1000 },   // 2000 users pile in over 5s
        { duration: "30s", target: 5000 },  // they keep refreshing
        { duration: "5s", target: 0 },
      ],
      startTime: "0s",
      tags: { scenario: "thundering_herd" },
      exec: "newArrival",
    },

    // Scenario 2: Steady state — queue full, users refreshing every ~10s.
    // Validates heartbeat updates, position updates, Redis connection pool.
    steady_queue: {
      executor: "constant-vus",
      vus: 1000,
      duration: "60s",
      startTime: "40s",   // start after thundering herd fills the queue
      tags: { scenario: "steady_queue" },
      exec: "queuedRefresher",
    },

  },

  thresholds: {
    // Only measure latency on waiting-room endpoints (not the upstream stub)
    "http_req_duration{name:waiting_room_main}": ["p(95)<500", "p(99)<1000"],
    "http_req_duration{name:waiting_room_refresh}": ["p(95)<500", "p(99)<1000"],
    // No 500s from the waiting room
    waiting_room_errors: ["count<5"],
  },
};

// ---------------------------------------------------------------------------
// Scenario: new arrival (no cookies)
// ---------------------------------------------------------------------------

export function newArrival() {
  // Use the VU's built-in cookie jar so the session persists across iterations.
  // Without this, each k6 loop creates a new user instead of simulating refreshes.
  const jar = http.cookieJar();
  const url = `${BASE_URL}/waiting-room?next=${PROTECTED_PATH}`;

  // If we already have a session cookie, this is a refresh, not a new arrival
  const cookies = jar.cookiesForURL(url);
  const isReturning = cookies && cookies["waiting_room_session_id"];

  const start = Date.now();

  const res = http.get(url, {
    redirects: 0, // don't follow — we want to inspect the 302
    tags: { name: isReturning ? "waiting_room_refresh" : "waiting_room_main" },
  });

  check(res, {
    "no 5xx": (r) => r.status < 500,
    "got a response": (r) => r.status > 0,
  }) || errorCounter.add(1);

  if (res.status === 302) {
    // Granted
    const elapsed = Date.now() - start;
    promotionLatency.add(elapsed);
    grantedCounter.add(1);

    check(res, {
      "redirects to protected path": (r) => (r.headers["Location"] || "").includes(PROTECTED_PATH),
      "sets access token cookie": (r) =>
        r.cookies["waiting_room_access_token"] !== undefined,
    });

    // Already granted — slow down, real users would leave the waiting room
    sleep(randomIntBetween(30, 60));
  } else if (res.status === 200) {
    if (!isReturning) {
      queuedCounter.add(1);

      check(res, {
        "shows queue page": (r) => r.body.includes("You are in the queue"),
        "shows position": (r) => r.body.includes("position in the queue is:"),
        "has session cookie": (r) =>
          r.cookies["waiting_room_session_id"] !== undefined,
      });
    }

    // Simulate the refresh interval the page would use (10-20s with jitter)
    sleep(randomIntBetween(8, 14));
  } else {
    errorCounter.add(1);
    sleep(5);
  }
}

// ---------------------------------------------------------------------------
// Scenario: already-queued user just refreshing (simulates steady queue load)
// Enqueues once, then keeps hitting the endpoint with the same session cookie.
// ---------------------------------------------------------------------------

export function queuedRefresher() {
  // Uses the VU's built-in cookie jar (default) so session persists across iterations.

  // Spread out initial requests — real queued users didn't all arrive at the same second
  sleep(randomIntBetween(0, 30));

  // First visit to get into the queue
  const first = http.get(`${BASE_URL}/waiting-room`, {
    redirects: 0,
    tags: { name: "queue_initial" },
  });

  if (first.status !== 200) {
    // Got granted straight away — that's fine too
    if (first.status === 302) grantedCounter.add(1);
    else errorCounter.add(1);
    return;
  }

  // Refresh periodically — simulates a real user waiting
  for (let i = 0; i < 4; i++) {
    sleep(randomIntBetween(9, 13));

    const res = http.get(`${BASE_URL}/waiting-room`, {
      redirects: 0,
      tags: { name: "queue_refresh" },
    });

    check(res, { "no 5xx": (r) => r.status < 500 }) || errorCounter.add(1);

    if (res.status === 302) {
      grantedCounter.add(1);
      break;
    }
  }
}
