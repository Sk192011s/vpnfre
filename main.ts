Deno.serve((req) => {
  const url = new URL(req.url);

  // JSON API (optional): /api/uuids?count=10
  if (url.pathname === "/api/uuids") {
    const countParam = Number(url.searchParams.get("count") ?? "1");
    const count = Number.isFinite(countParam)
      ? Math.min(Math.max(Math.floor(countParam), 1), 1000)
      : 1;

    const uuids = Array.from({ length: count }, () => crypto.randomUUID());
    return Response.json({
      success: true,
      count,
      uuids,
      commaSeparated: uuids.join(","),
    });
  }

  // Main UI
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>UUID v4 Bulk Generator</title>
  <meta name="description" content="Generate UUID v4 in bulk with comma-separated copy." />
  <style>
    :root{
      --bg: #0b1020;
      --panel: rgba(255,255,255,0.06);
      --panel-2: rgba(255,255,255,0.04);
      --border: rgba(255,255,255,0.12);
      --text: #eaf0ff;
      --muted: #aeb8d8;
      --accent: #7c9cff;
      --accent-2: #5be7c4;
      --danger: #ff7a90;
      --shadow: 0 10px 35px rgba(0,0,0,.35);
      --radius: 18px;
    }

    * { box-sizing: border-box; }
    html, body { height: 100%; }

    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      color: var(--text);
      background:
        radial-gradient(900px 500px at -10% -10%, rgba(124,156,255,.18), transparent 55%),
        radial-gradient(800px 450px at 110% 0%, rgba(91,231,196,.12), transparent 55%),
        linear-gradient(180deg, #090d1a, #0b1020 40%, #0a0f1d);
      padding: 20px;
    }

    .wrap{
      max-width: 980px;
      margin: 0 auto;
      display: grid;
      gap: 16px;
    }

    .card{
      background: linear-gradient(180deg, var(--panel), var(--panel-2));
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
    }

    .header{
      padding: 20px;
      display: grid;
      gap: 8px;
    }

    .title{
      display:flex;
      align-items:center;
      gap:10px;
      font-size: 1.4rem;
      font-weight: 700;
      letter-spacing: .2px;
    }

    .badge{
      font-size: 12px;
      color: #dbe6ff;
      border: 1px solid rgba(255,255,255,.16);
      background: rgba(124,156,255,.12);
      padding: 4px 8px;
      border-radius: 999px;
    }

    .subtitle{
      color: var(--muted);
      line-height: 1.5;
      font-size: .95rem;
    }

    .controls{
      padding: 16px 20px 20px;
      display:grid;
      gap:14px;
      border-top: 1px solid var(--border);
    }

    .row{
      display:flex;
      flex-wrap: wrap;
      gap:10px;
      align-items:center;
    }

    .label{
      font-size: .9rem;
      color: var(--muted);
      min-width: 72px;
    }

    .input{
      width: 120px;
      height: 42px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,.04);
      color: var(--text);
      padding: 0 12px;
      outline: none;
      font-size: .95rem;
    }
    .input:focus{
      border-color: rgba(124,156,255,.55);
      box-shadow: 0 0 0 4px rgba(124,156,255,.12);
    }

    .btn{
      height: 42px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,.05);
      color: var(--text);
      border-radius: 12px;
      padding: 0 14px;
      cursor: pointer;
      font-weight: 600;
      transition: .15s ease;
      user-select: none;
    }

    .btn:hover{ transform: translateY(-1px); background: rgba(255,255,255,.08); }
    .btn:active{ transform: translateY(0); }

    .btn.primary{
      border-color: rgba(124,156,255,.35);
      background: linear-gradient(180deg, rgba(124,156,255,.28), rgba(124,156,255,.16));
    }

    .btn.copy{
      border-color: rgba(91,231,196,.32);
      background: linear-gradient(180deg, rgba(91,231,196,.22), rgba(91,231,196,.12));
    }

    .btn.ghost{
      background: transparent;
    }

    .btn.danger{
      border-color: rgba(255,122,144,.35);
      background: linear-gradient(180deg, rgba(255,122,144,.18), rgba(255,122,144,.10));
    }

    .hint{
      color: var(--muted);
      font-size: .85rem;
    }

    .output-card{
      padding: 14px;
      display:grid;
      gap:10px;
    }

    .toolbar{
      display:flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap:10px;
      align-items:center;
      padding: 6px 6px 0;
    }

    .stats{
      color: var(--muted);
      font-size: .9rem;
      display:flex;
      gap:14px;
      flex-wrap: wrap;
    }

    .output{
      width: 100%;
      min-height: 250px;
      resize: vertical;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: rgba(8,12,24,.75);
      color: #e8f1ff;
      padding: 14px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      line-height: 1.5;
      font-size: .92rem;
      outline: none;
    }
    .output:focus{
      border-color: rgba(124,156,255,.55);
      box-shadow: 0 0 0 4px rgba(124,156,255,.12);
    }

    .footer{
      color: var(--muted);
      text-align:center;
      font-size: .82rem;
      padding: 8px 0 2px;
    }

    .ok{
      color: #baf7e7;
    }
    .warn{
      color: #ffd9a1;
    }

    @media (max-width: 640px){
      .label{ min-width: auto; width: 100%; }
      .input{ width: 100%; }
      .row{ align-items: stretch; }
      .btn{ flex: 1 1 auto; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="card">
      <div class="header">
        <div class="title">
          <span>UUID v4 Bulk Generator</span>
          <span class="badge">Deno</span>
        </div>
        <div class="subtitle">
          Generate UUID v4 in bulk and copy all as a single comma-separated string.
        </div>
      </div>

      <div class="controls">
        <div class="row">
          <span class="label">Count</span>
          <input id="countInput" class="input" type="number" min="1" max="1000" value="10" />
          <button class="btn" data-count="10">10</button>
          <button class="btn" data-count="100">100</button>
          <button class="btn" data-count="500">500</button>
          <button class="btn primary" id="generateBtn">Generate</button>
        </div>

        <div class="row">
          <span class="label">Actions</span>
          <button class="btn copy" id="copyBtn">Copy All (comma)</button>
          <button class="btn ghost" id="selectBtn">Select Output</button>
          <button class="btn danger" id="clearBtn">Clear</button>
        </div>

        <div class="hint">
          Max 1000 UUIDs per generation. Output format: <code>uuid1,uuid2,uuid3,...</code>
        </div>
      </div>
    </section>

    <section class="card output-card">
      <div class="toolbar">
        <div class="stats">
          <span>Total UUIDs: <strong id="totalCount">0</strong></span>
          <span>Characters: <strong id="charCount">0</strong></span>
        </div>
        <div id="status" class="hint">Ready</div>
      </div>

      <textarea id="output" class="output" spellcheck="false" placeholder="Generated UUIDs will appear here..."></textarea>
    </section>

    <div class="footer">
      UUIDs are generated in your browser using <code>crypto.randomUUID()</code> (UUID v4).
    </div>
  </div>

  <script>
    const countInput = document.getElementById("countInput");
    const output = document.getElementById("output");
    const totalCountEl = document.getElementById("totalCount");
    const charCountEl = document.getElementById("charCount");
    const statusEl = document.getElementById("status");

    const generateBtn = document.getElementById("generateBtn");
    const copyBtn = document.getElementById("copyBtn");
    const selectBtn = document.getElementById("selectBtn");
    const clearBtn = document.getElementById("clearBtn");

    function setStatus(text, type = "normal") {
      statusEl.textContent = text;
      statusEl.className = "hint" + (type === "ok" ? " ok" : type === "warn" ? " warn" : "");
    }

    function clampCount(n) {
      if (!Number.isFinite(n)) return 10;
      return Math.min(Math.max(Math.floor(n), 1), 1000);
    }

    function parseOutputCount(text) {
      const t = text.trim();
      if (!t) return 0;
      return t.split(",").filter(Boolean).length;
    }

    function updateStats() {
      const text = output.value || "";
      totalCountEl.textContent = String(parseOutputCount(text));
      charCountEl.textContent = String(text.length);
    }

    function generateUUIDs(count) {
      const arr = [];
      for (let i = 0; i < count; i++) {
        arr.push(crypto.randomUUID());
      }
      return arr;
    }

    function handleGenerate() {
      const count = clampCount(Number(countInput.value));
      countInput.value = String(count);

      const uuids = generateUUIDs(count);
      output.value = uuids.join(",");
      updateStats();
      setStatus("Generated " + count + " UUIDs", "ok");
    }

    async function handleCopy() {
      const text = output.value.trim();
      if (!text) {
        setStatus("Nothing to copy", "warn");
        return;
      }
      try {
        await navigator.clipboard.writeText(text);
        setStatus("Copied all UUIDs (comma-separated)", "ok");
      } catch {
        // fallback
        output.focus();
        output.select();
        document.execCommand("copy");
        setStatus("Copied (fallback)", "ok");
      }
    }

    function handleClear() {
      output.value = "";
      updateStats();
      setStatus("Cleared", "ok");
    }

    // Preset buttons
    document.querySelectorAll("[data-count]").forEach((btn) => {
      btn.addEventListener("click", () => {
        countInput.value = btn.getAttribute("data-count");
        handleGenerate();
      });
    });

    generateBtn.addEventListener("click", handleGenerate);
    copyBtn.addEventListener("click", handleCopy);
    clearBtn.addEventListener("click", handleClear);

    selectBtn.addEventListener("click", () => {
      output.focus();
      output.select();
      setStatus("Output selected", "ok");
    });

    countInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") handleGenerate();
    });

    output.addEventListener("input", updateStats);

    // Initial generate
    handleGenerate();
  </script>
</body>
</html>`;

  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
});
