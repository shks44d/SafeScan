"use strict";
const CHUNK_SIZE = 250;
const PARALLEL_CHUNKS = 3;
const CHUNK_RETRIES = 4;
const COMMON_PORTS = [
  20, 21, 22, 23, 24, 25, 53, 67, 68, 69, 80, 81, 88, 110, 111, 123, 135, 136,
  137, 138, 139, 143, 161, 162, 179, 389, 443, 444, 445, 465, 500, 514, 515,
  548, 554, 587, 631, 636, 873, 902, 989, 990, 993, 994, 995, 1080, 1099, 1194,
  1433, 1521, 1723, 1883, 2049, 2181, 2375, 2376, 2379, 3000, 3306, 3389, 3690,
  4000, 4369, 5000, 5060, 5432, 5672, 5900, 5985, 5986, 6379, 6443, 6667, 7001,
  8000, 8008, 8080, 8081, 8086, 8088, 8181, 8443, 8500, 8888, 9000, 9042, 9090,
  9091, 9092, 9200, 9300, 9418, 9443, 10000, 10250, 11211, 15672, 27015, 27017,
  27018, 50000,
];
const $ = (selector) => document.querySelector(selector);
let resultData = null;
let active = false;
let cancelRequested = false;
let controllers = new Set();
let sortState = { key: "port", direction: 1 };

function rangeChunks(start, end) {
  const chunks = [];
  for (let port = start; port <= end; port += CHUNK_SIZE)
    chunks.push([port, Math.min(port + CHUNK_SIZE - 1, end)]);
  return chunks;
}
function parsePortList(value) {
  if (!value.trim() || value.length > 10000)
    throw new Error("Enter a port list, up to 10,000 characters.");
  const ports = new Set();
  for (const token of value.split(",")) {
    const match = token.trim().match(/^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/);
    if (!match)
      throw new Error("Use ports and ranges such as 22,80,443,8000-8100.");
    const start = Number(match[1]);
    const end = Number(match[2] || match[1]);
    if (start < 1 || end > 65535 || start > end)
      throw new Error(
        "Ports must be between 1 and 65,535, with ranges in ascending order.",
      );
    for (let port = start; port <= end; port += 1) ports.add(port);
  }
  return [...ports].sort((a, b) => a - b);
}
function portsToChunks(ports) {
  const chunks = [];
  for (const port of ports) {
    const last = chunks[chunks.length - 1];
    if (last && port === last[1] + 1 && last[1] - last[0] + 1 < CHUNK_SIZE)
      last[1] = port;
    else chunks.push([port, port]);
  }
  return chunks;
}
function selectedChunks() {
  const mode = $("#scan-mode").value;
  if (mode === "common") return portsToChunks(COMMON_PORTS);
  if (mode === "well-known") return rangeChunks(1, 1024);
  if (mode === "all") return rangeChunks(1, 65535);
  if (mode === "list")
    return portsToChunks(parsePortList($("#port-list").value));
  const start = Number($("#start-port").value);
  const end = Number($("#end-port").value);
  if (
    !Number.isInteger(start) ||
    !Number.isInteger(end) ||
    start < 1 ||
    end > 65535 ||
    start > end ||
    !$("#end-port").value
  )
    throw new Error(
      "Enter whole ports from 1 to 65,535. Start port must not exceed end port.",
    );
  return rangeChunks(start, end);
}
function validateSelection() {
  $("#range-error").textContent = "";
  $("#list-error").textContent = "";
  try {
    selectedChunks();
    return true;
  } catch (error) {
    $(
      $("#scan-mode").value === "list" ? "#list-error" : "#range-error",
    ).textContent = error.message;
    return false;
  }
}
$("#scan-mode").addEventListener("change", () => {
  $("#custom-range").hidden = $("#scan-mode").value !== "custom";
  $("#list-field").hidden = $("#scan-mode").value !== "list";
  validateSelection();
});
for (const id of ["#start-port", "#end-port", "#port-list"])
  $(id).addEventListener("input", validateSelection);

class ApiError extends Error {
  constructor(message, status, retryAfter = 0) {
    super(message);
    this.status = status;
    this.retryAfter = retryAfter;
  }
}
async function api(url, body, controller) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: controller.signal,
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const header = response.headers.get("Retry-After");
    const seconds = Number(header);
    const delay =
      header && !Number.isFinite(seconds)
        ? Math.max(0, Date.parse(header) - Date.now())
        : seconds * 1000;
    throw new ApiError(
      payload?.error || "The request failed. Please retry unfinished ports.",
      response.status,
      delay || 0,
    );
  }
  if (!payload || typeof payload !== "object")
    throw new Error("The server returned an invalid response.");
  return payload;
}
function retryDelay(milliseconds, signal) {
  return new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      reject(new DOMException("Cancelled", "AbortError"));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, milliseconds);
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  });
}
async function scanChunk(chunk, controller, scan) {
  for (let attempt = 1; attempt <= CHUNK_RETRIES; attempt += 1) {
    try {
      const reply = await api(
        "/api/scan",
        {
          ip: scan.ip,
          host: scan.target,
          start: chunk.start,
          end: chunk.end,
          authorized: true,
        },
        controller,
      );
      if (
        reply.start !== chunk.start ||
        reply.end !== chunk.end ||
        reply.scanned !== chunk.end - chunk.start + 1 ||
        !Array.isArray(reply.open)
      )
        throw new Error("The server returned an inconsistent scan chunk.");
      return reply;
    } catch (error) {
      const transient =
        error instanceof TypeError ||
        [500, 502, 503, 504].includes(error.status);
      if (!transient || attempt === CHUNK_RETRIES || controller.signal.aborted)
        throw error;
      await retryDelay(
        Math.max(error.retryAfter || 0, 600 * 2 ** (attempt - 1)) +
          Math.random() * 250,
        controller.signal,
      );
    }
  }
}
function coverage(chunks) {
  const counts = { completed: 0, failed: 0, pending: 0 };
  for (const chunk of chunks)
    counts[
      chunk.status === "complete"
        ? "completed"
        : chunk.status === "failed"
          ? "failed"
          : "pending"
    ] += chunk.end - chunk.start + 1;
  return counts;
}
function formatDuration(seconds) {
  return `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
}
function snapshot(scan = resultData) {
  const counts = coverage(scan.chunks);
  return {
    schemaVersion: 2,
    appVersion: "2.0.0",
    target: scan.target,
    ip: scan.ip,
    ips: scan.ips,
    mode: scan.mode,
    status: scan.status,
    startedAt: scan.startedAt,
    total: scan.total,
    scanned: counts.completed,
    ...counts,
    durationSeconds: scan.durationSeconds,
    scope: scan.chunks.map(({ start, end, status, error }) => ({
      start,
      end,
      status,
      error,
    })),
    open: [...scan.open].sort((a, b) => a.port - b.port),
  };
}
function renderProgress() {
  if (!resultData) return;
  const counts = coverage(resultData.chunks);
  const percent =
    counts.completed === resultData.total
      ? 100
      : Math.floor((counts.completed / resultData.total) * 100);
  $("#progress").value = percent;
  $("#progress-percent").textContent = `${percent}%`;
  $("#progress-copy").textContent =
    `Completed ${counts.completed.toLocaleString()} / ${resultData.total.toLocaleString()} ports · Failed ${counts.failed.toLocaleString()} · Pending ${counts.pending.toLocaleString()}`;
  $("#summary-scanned").textContent =
    `${counts.completed.toLocaleString()} / ${resultData.total.toLocaleString()}`;
  $("#summary-duration").textContent = formatDuration(
    resultData.durationSeconds,
  );
  $("#elapsed").textContent = formatDuration(resultData.durationSeconds);
}
function productLabel(item) {
  return [item.product, item.version].filter(Boolean).join(" ") || "—";
}
function escapeHtml(value) {
  const element = document.createElement("span");
  element.textContent = value == null ? "" : String(value);
  return element.innerHTML;
}
function filteredResults(rows, query, confidence) {
  return rows.filter(
    (item) =>
      (!confidence || item.confidence === confidence) &&
      `${item.port} ${item.service} ${productLabel(item)}`
        .toLowerCase()
        .includes(query.trim().toLowerCase()),
  );
}
function renderResults() {
  if (!resultData) return;
  const rows = filteredResults(
    resultData.open,
    $("#result-search").value,
    $("#confidence-filter").value,
  ).sort((a, b) => {
    const left =
      sortState.key === "product" ? productLabel(a) : a[sortState.key];
    const right =
      sortState.key === "product" ? productLabel(b) : b[sortState.key];
    return (
      (typeof left === "number"
        ? left - right
        : String(left).localeCompare(String(right))) * sortState.direction
    );
  });
  $("#results-body").replaceChildren(
    ...rows.map((item) => {
      const row = document.createElement("tr");
      row.innerHTML = `<td><strong>${escapeHtml(item.port)}</strong></td><td><span class="open-state">open</span></td><td>${escapeHtml(item.service)}</td><td>${escapeHtml(productLabel(item))}<small>${item.confidence === "banner" ? "Banner observed" : "Port guess"}</small></td><td>${item.banner ? "<details><summary>View banner</summary><code></code></details>" : '<span class="muted">No banner</span>'}</td>`;
      if (item.banner) row.querySelector("code").textContent = item.banner;
      return row;
    }),
  );
  $("#summary-open").textContent = resultData.open.length;
  $("#filter-count").textContent =
    `Showing ${rows.length} of ${resultData.open.length} open ports. Exports include all results.`;
  $("#empty-state").hidden = rows.length !== 0;
  $("#empty-state strong").textContent = resultData.open.length
    ? "No matching open ports"
    : "No open ports found in completed checks";
}
async function worker(queue, scan) {
  while (queue.length && !cancelRequested) {
    const chunk = queue.shift();
    const controller = new AbortController();
    controllers.add(controller);
    chunk.status = "running";
    try {
      const reply = await scanChunk(chunk, controller, scan);
      if (cancelRequested) {
        chunk.status = "pending";
        continue;
      }
      chunk.status = "complete";
      delete chunk.error;
      const found = new Map(scan.open.map((item) => [item.port, item]));
      for (const item of reply.open)
        if (
          Number.isInteger(item.port) &&
          item.port >= chunk.start &&
          item.port <= chunk.end
        )
          found.set(item.port, item);
      scan.open = [...found.values()];
    } catch (error) {
      chunk.status = controller.signal.aborted ? "pending" : "failed";
      chunk.error = controller.signal.aborted ? undefined : error.message;
    } finally {
      controllers.delete(controller);
      renderProgress();
      renderResults();
    }
  }
}
function controls(running) {
  $("#scan-button").disabled = running;
  $("#cancel-button").hidden = !running;
  $("#retry-button").hidden =
    running ||
    !resultData ||
    coverage(resultData.chunks).completed === resultData.total;
  $("#scan-again").disabled = running;
  for (const field of document.querySelectorAll(
    "#scan-form input, #scan-form select",
  ))
    field.disabled = running;
}
async function runScan(scan) {
  active = true;
  cancelRequested = false;
  controls(true);
  scan.status = "running";
  $("#status-label").textContent = "Scanning target…";
  $("#result-notice").textContent =
    "Scan in progress. Open ports appear as chunks finish.";
  const started = Date.now();
  const previousDuration = scan.durationSeconds;
  const updateTime = () => {
    scan.durationSeconds =
      previousDuration + Math.floor((Date.now() - started) / 1000);
    renderProgress();
  };
  const timer = setInterval(updateTime, 1000);
  const queue = scan.chunks.filter((chunk) => chunk.status !== "complete");
  for (const chunk of queue) {
    chunk.status = "pending";
    delete chunk.error;
  }
  renderProgress();
  try {
    await Promise.all(
      Array.from({ length: Math.min(PARALLEL_CHUNKS, queue.length) }, () =>
        worker(queue, scan),
      ),
    );
  } finally {
    clearInterval(timer);
    updateTime();
    const counts = coverage(scan.chunks);
    scan.status =
      counts.completed === scan.total
        ? "complete"
        : cancelRequested
          ? "cancelled"
          : "partial";
    $("#status-label").textContent =
      scan.status === "complete" ? "Scan complete" : "Partial results";
    $("#result-notice").textContent =
      scan.status === "complete"
        ? "All selected ports were checked. Closed and filtered ports are not listed."
        : `${cancelRequested ? "Scan cancelled." : "Some checks failed."} These are partial results. Retry unfinished ports to continue. Completed chunks will not be repeated.`;
    active = false;
    controls(false);
    renderResults();
  }
}
$("#scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (active || !validateSelection()) return;
  $("#form-error").hidden = true;
  $("#target-error").textContent = "";
  if (!$("#authorized").checked) {
    $("#form-error").textContent =
      "Confirm that you have permission to scan this target.";
    $("#form-error").hidden = false;
    return;
  }
  const target = $("#target").value.trim();
  if (!target) {
    $("#target-error").textContent = "Enter a domain, IP address, or URL.";
    return;
  }
  const selected = selectedChunks();
  const modeLabel = $("#scan-mode").selectedOptions[0].textContent;
  active = true;
  cancelRequested = false;
  resultData = null;
  controllers = new Set();
  $("#results").hidden = true;
  $("#scan-status").hidden = false;
  $("#progress").value = 0;
  $("#progress-percent").textContent = "0%";
  $("#elapsed").textContent = "00:00";
  $("#progress-copy").textContent = "Resolving target…";
  $("#status-label").textContent = "Resolving target…";
  controls(true);
  const controller = new AbortController();
  controllers.add(controller);
  try {
    const resolved = await api("/api/resolve", { target }, controller);
    if (cancelRequested) return;
    resultData = {
      target: resolved.host,
      ip: resolved.ip,
      ips: resolved.ips,
      mode: modeLabel,
      total: selected.reduce((sum, [start, end]) => sum + end - start + 1, 0),
      chunks: selected.map(([start, end]) => ({
        start,
        end,
        status: "pending",
      })),
      open: [],
      durationSeconds: 0,
      startedAt: new Date().toISOString(),
      status: "running",
    };
    $("#summary-target").textContent = `${resolved.host} (${resolved.ip})`;
    $("#result-search").value = "";
    $("#confidence-filter").value = "";
    $("#results").hidden = false;
    renderResults();
    await runScan(resultData);
  } catch (error) {
    $("#status-label").textContent = cancelRequested
      ? "Scan cancelled"
      : "Unable to start scan";
    if (!cancelRequested) {
      $("#form-error").textContent = error.message;
      $("#form-error").hidden = false;
    }
  } finally {
    controllers.delete(controller);
    active = false;
    controls(false);
    if (cancelRequested && !resultData)
      $("#status-label").textContent = "Scan cancelled";
  }
});
$("#cancel-button").addEventListener("click", () => {
  cancelRequested = true;
  for (const controller of controllers) controller.abort();
});
$("#retry-button").addEventListener("click", async () => {
  if (!active && resultData) await runScan(resultData);
});
for (const selector of ["#result-search", "#confidence-filter"])
  $(selector).addEventListener("input", renderResults);
document.querySelectorAll(".sort-button").forEach((button) =>
  button.addEventListener("click", () => {
    sortState.direction =
      sortState.key === button.dataset.sort ? sortState.direction * -1 : 1;
    sortState.key = button.dataset.sort;
    renderResults();
  }),
);
function download(filename, type, content) {
  const link = document.createElement("a");
  const url = URL.createObjectURL(new Blob([content], { type }));
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function csvCell(value) {
  let text = String(value ?? "");
  const candidate = text.replace(/^[\s\u0000-\u001f\u007f-\u009f]+/u, "");
  if (/^[=+\-@＝＋－＠]/u.test(candidate)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}
$("#download-json").addEventListener("click", () =>
  download(
    "safescan-results.json",
    "application/json",
    JSON.stringify(snapshot(), null, 2),
  ),
);
$("#download-csv").addEventListener("click", () => {
  const data = snapshot();
  const rows = [
    [
      "Scan status",
      "Target",
      "IP",
      "Selected ports",
      "Completed",
      "Failed",
      "Pending",
      "Port",
      "State",
      "Service",
      "Product",
      "Version",
      "Confidence",
      "Banner",
    ],
    ...data.open.map((item) => [
      data.status,
      data.target,
      data.ip,
      data.total,
      data.completed,
      data.failed,
      data.pending,
      item.port,
      item.state,
      item.service,
      item.product,
      item.version,
      item.confidence,
      item.banner,
    ]),
  ];
  if (!data.open.length)
    rows.push([
      data.status,
      data.target,
      data.ip,
      data.total,
      data.completed,
      data.failed,
      data.pending,
    ]);
  download(
    "safescan-results.csv",
    "text/csv",
    rows.map((row) => row.map(csvCell).join(",")).join("\r\n"),
  );
});
$("#copy-results").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(JSON.stringify(snapshot(), null, 2));
    $("#copy-results").textContent = "Copied";
  } catch {
    $("#copy-results").textContent = "Copy unavailable · use download";
  }
  setTimeout(() => {
    $("#copy-results").textContent = "Copy results";
  }, 1800);
});
$("#scan-again").addEventListener("click", () => {
  if (active) return;
  resultData = null;
  $("#scan-status").hidden = true;
  $("#results").hidden = true;
  $("#scan-form").scrollIntoView({ behavior: "smooth" });
  $("#target").focus();
});
window.addEventListener("beforeunload", (event) => {
  if (active) {
    event.preventDefault();
    event.returnValue = "";
  }
});
