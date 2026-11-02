const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

function loadApp() {
  const element = { addEventListener() {}, value: "", hidden: true };
  const context = vm.createContext({
    document: { querySelector: () => element, querySelectorAll: () => [] },
    window: { addEventListener() {} },
  });
  vm.runInContext(
    fs.readFileSync(path.join(__dirname, "../static/js/app.js"), "utf8"),
    context,
  );
  return context;
}

test("CSV formulas and whitespace/control-prefixed formulas are text", () => {
  const context = loadApp();
  for (const value of [
    "=1+1",
    "+SUM(A1)",
    "-1+2",
    "@SUM(A1)",
    "\t=1+1",
    "\r\n=1+1",
    "\0=1+1",
    "\u00a0=1+1",
    "\ufeff=1+1",
    "＝1+1",
    "＋1",
    "－1",
    "＠SUM(A1)",
  ]) {
    context.input = value;
    const output = vm.runInContext("csvCell(input)", context);
    assert.equal(output[0], '"');
    assert.equal(output[1], "'");
  }
});

test("Port lists deduplicate, sort, preserve gaps, and reject malformed tokens", () => {
  const context = loadApp();
  assert.equal(
    vm.runInContext(
      "JSON.stringify(parsePortList('443,22,80,80,8000-8002'))",
      context,
    ),
    "[22,80,443,8000,8001,8002]",
  );
  assert.equal(
    vm.runInContext(
      "JSON.stringify(portsToChunks(parsePortList('22,80,8000-8002')))",
      context,
    ),
    "[[22,22],[80,80],[8000,8002]]",
  );
  for (const value of [
    "",
    "0",
    "65536",
    "100-50",
    "22,,80",
    "22.5",
    "80;443",
    "-1",
    "1e2",
  ]) {
    context.value = value;
    assert.throws(() => vm.runInContext("parsePortList(value)", context));
  }
});

test("Coverage counts completed, failed and unfinished ports without rounding up", () => {
  const context = loadApp();
  assert.equal(
    vm.runInContext(
      "JSON.stringify(coverage([{start:1,end:250,status:'complete'},{start:251,end:500,status:'failed'},{start:501,end:535,status:'running'}]))",
      context,
    ),
    '{"completed":250,"failed":250,"pending":35}',
  );
});

test("Filters combine confidence and case-insensitive product/service search", () => {
  const context = loadApp();
  context.rows = [
    {
      port: 22,
      service: "ssh",
      product: "OpenSSH",
      version: "9.6",
      confidence: "banner",
    },
    {
      port: 443,
      service: "https",
      product: null,
      version: null,
      confidence: "port-guess",
    },
  ];
  assert.equal(
    vm.runInContext("filteredResults(rows,'openssh','banner').length", context),
    1,
  );
  assert.equal(
    vm.runInContext("filteredResults(rows,'443','banner').length", context),
    0,
  );
  assert.equal(
    vm.runInContext(
      "filteredResults(rows,'HTTPS','port-guess').length",
      context,
    ),
    1,
  );
});

test("Ordinary CSV data and CSV syntax remain intact", () => {
  const context = loadApp();
  for (const [value, expected] of [
    ["SSH-2.0-OpenSSH_9.6", '"SSH-2.0-OpenSSH_9.6"'],
    ['hello,"world"\nnext', '"hello,""world""\nnext"'],
    ["café", '"café"'],
    [null, '""'],
    [443, '"443"'],
  ]) {
    context.input = value;
    assert.equal(vm.runInContext("csvCell(input)", context), expected);
  }
});

test("All-port range still covers every port exactly once in bounded chunks", () => {
  const chunks = vm.runInContext("rangeChunks(1, 65535)", loadApp());
  let next = 1;
  for (const [start, end] of chunks) {
    assert.equal(start, next);
    assert.ok(end - start + 1 <= 250);
    next = end + 1;
  }
  assert.equal(next, 65536);
});

test("Transient chunk failure honors Retry-After and retries the same scope", async () => {
  const context = loadApp();
  context.AbortController = AbortController;
  context.setTimeout = setTimeout;
  context.clearTimeout = clearTimeout;
  context.DOMException = DOMException;
  let calls = 0;
  const scopes = [];
  context.fetch = async (_url, options) => {
    scopes.push(JSON.parse(options.body));
    calls += 1;
    return calls === 1
      ? {
          ok: false,
          status: 503,
          headers: { get: () => "1" },
          json: async () => ({ error: "Busy" }),
        }
      : {
          ok: true,
          headers: { get: () => null },
          json: async () => ({ start: 1, end: 2, scanned: 2, open: [] }),
        };
  };
  const started = Date.now();
  const reply = await vm.runInContext(
    "scanChunk({start:1,end:2},new AbortController(),{ip:'8.8.8.8',target:'example.com'})",
    context,
  );
  assert.equal(reply.scanned, 2);
  assert.equal(calls, 2);
  assert.deepEqual(scopes[0], scopes[1]);
  assert.ok(Date.now() - started >= 1000);
});

test("Snapshot exports actual coverage and preserves the selected scope", () => {
  const context = loadApp();
  context.scan = {
    target: "example.com",
    ip: "8.8.8.8",
    ips: ["8.8.8.8"],
    mode: "Custom range",
    status: "cancelled",
    total: 535,
    startedAt: "2026-11-02",
    durationSeconds: 3,
    open: [],
    chunks: [
      { start: 1, end: 250, status: "complete" },
      { start: 251, end: 535, status: "pending" },
    ],
  };
  const output = JSON.parse(
    vm.runInContext("JSON.stringify(snapshot(scan))", context),
  );
  assert.equal(output.schemaVersion, 2);
  assert.equal(output.scanned, 250);
  assert.equal(output.pending, 285);
  assert.equal(output.status, "cancelled");
  assert.deepEqual(
    output.scope.map(({ start, end }) => [start, end]),
    [
      [1, 250],
      [251, 535],
    ],
  );
});
