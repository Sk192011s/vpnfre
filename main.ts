import { exists } from "https://deno.land/std@0.224.0/fs/exists.ts";

// ─── Environment Variables ───────────────────────────────────────────
const envUUID = Deno.env.get('UUID') || '';
const proxyIPs = (Deno.env.get('PROXYIP') || '').split(',').map(ip => ip.trim()).filter(Boolean);
const credit = Deno.env.get('CREDIT') || '';
const webPassword = Deno.env.get('WEB_PASSWORD') || '';
const wsPath = Deno.env.get('WS_PATH') || '/ws';
const webUsername = Deno.env.get('WEB_USERNAME') || '';
const stickyProxyIPEnv = Deno.env.get('STICKY_PROXYIP') || '';
const CONFIG_FILE = 'config.json';
const KEYS_FILE = 'generated_keys.json';

// ─── Weekly Cycle Configuration ──────────────────────────────────────
// CYCLE_START_DAY: 0=Sunday, 1=Monday, ... 6=Saturday
const CYCLE_START_DAY = parseInt(Deno.env.get('CYCLE_START_DAY') || '1'); // default Monday
const CYCLE_DURATION_DAYS = 7;

interface Config {
  uuid?: string;
}

interface GeneratedKey {
  id: string;
  uuid: string;
  vlessKey: string;
  createdAt: string;
  cycleStart: string;
  cycleEnd: string;
}

interface KeysStore {
  keys: GeneratedKey[];
  currentCycleStart: string;
  currentCycleEnd: string;
}

// ─── Weekly Cycle Helpers ────────────────────────────────────────────
function getCurrentCycleStart(): Date {
  const now = new Date();
  const dayOfWeek = now.getUTCDay(); // 0=Sun, 1=Mon, ...
  let diff = dayOfWeek - CYCLE_START_DAY;
  if (diff < 0) diff += 7;
  const cycleStart = new Date(now);
  cycleStart.setUTCDate(now.getUTCDate() - diff);
  cycleStart.setUTCHours(0, 0, 0, 0);
  return cycleStart;
}

function getCurrentCycleEnd(): Date {
  const cycleStart = getCurrentCycleStart();
  const cycleEnd = new Date(cycleStart);
  cycleEnd.setUTCDate(cycleStart.getUTCDate() + CYCLE_DURATION_DAYS);
  cycleEnd.setUTCHours(0, 0, 0, 0);
  return cycleEnd;
}

function formatDate(d: Date): string {
  return d.toISOString().split('T')[0];
}

function formatDateReadable(d: Date): string {
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  return `${days[d.getUTCDay()]}, ${months[d.getUTCMonth()]} ${d.getUTCDate()}, ${d.getUTCFullYear()}`;
}

// ─── Keys Store ──────────────────────────────────────────────────────
async function loadKeysStore(): Promise<KeysStore> {
  const cycleStart = formatDate(getCurrentCycleStart());
  const cycleEnd = formatDate(getCurrentCycleEnd());

  if (await exists(KEYS_FILE)) {
    try {
      const data = await Deno.readTextFile(KEYS_FILE);
      const store: KeysStore = JSON.parse(data);
      // If cycle has changed, reset all keys
      if (store.currentCycleStart !== cycleStart) {
        console.log(`New cycle started. Old: ${store.currentCycleStart}, New: ${cycleStart}. Resetting keys.`);
        const newStore: KeysStore = {
          keys: [],
          currentCycleStart: cycleStart,
          currentCycleEnd: cycleEnd,
        };
        await saveKeysStore(newStore);
        return newStore;
      }
      return store;
    } catch (e) {
      console.warn(`Error reading ${KEYS_FILE}:`, (e as Error).message);
    }
  }
  const newStore: KeysStore = {
    keys: [],
    currentCycleStart: cycleStart,
    currentCycleEnd: cycleEnd,
  };
  await saveKeysStore(newStore);
  return newStore;
}

async function saveKeysStore(store: KeysStore): Promise<void> {
  try {
    await Deno.writeTextFile(KEYS_FILE, JSON.stringify(store, null, 2));
  } catch (e) {
    console.error(`Failed to save ${KEYS_FILE}:`, (e as Error).message);
  }
}

// ─── HTML Escape (XSS Prevention) ───────────────────────────────────
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ─── Constant-Time Comparison ────────────────────────────────────────
function constantTimeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  if (bufA.length !== bufB.length) {
    let dummy = 0;
    for (let i = 0; i < bufA.length; i++) {
      dummy |= bufA[i] ^ (bufB[i % bufB.length] || 0);
    }
    return false;
  }
  let result = 0;
  for (let i = 0; i < bufA.length; i++) {
    result |= bufA[i] ^ bufB[i];
  }
  return result === 0;
}

// ─── Rate Limiter ────────────────────────────────────────────────────
const MAX_TRACKED_IPS = 10000;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const RATE_LIMIT_MAX_ATTEMPTS = 5;
const loginAttempts = new Map<string, { count: number; lastAttempt: number }>();

// Generate rate limiter (prevent abuse)
const GENERATE_RATE_WINDOW = 60 * 1000; // 1 minute
const GENERATE_MAX_ATTEMPTS = 3;
const generateAttempts = new Map<string, { count: number; lastAttempt: number }>();

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of loginAttempts) {
    if (now - record.lastAttempt > RATE_LIMIT_WINDOW) {
      loginAttempts.delete(ip);
    }
  }
  for (const [ip, record] of generateAttempts) {
    if (now - record.lastAttempt > GENERATE_RATE_WINDOW) {
      generateAttempts.delete(ip);
    }
  }
}, 30 * 60 * 1000);

function pruneRateLimitMap(): void {
  if (loginAttempts.size > MAX_TRACKED_IPS) {
    const entries = Array.from(loginAttempts.entries());
    entries.sort((a, b) => a[1].lastAttempt - b[1].lastAttempt);
    const toRemove = Math.floor(entries.length / 2);
    for (let i = 0; i < toRemove; i++) {
      loginAttempts.delete(entries[i][0]);
    }
  }
}

function isRateLimited(ip: string): boolean {
  pruneRateLimitMap();
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record) {
    loginAttempts.set(ip, { count: 1, lastAttempt: now });
    return false;
  }
  if (now - record.lastAttempt > RATE_LIMIT_WINDOW) {
    loginAttempts.set(ip, { count: 1, lastAttempt: now });
    return false;
  }
  record.count++;
  record.lastAttempt = now;
  return record.count > RATE_LIMIT_MAX_ATTEMPTS;
}

function isGenerateRateLimited(ip: string): boolean {
  const now = Date.now();
  const record = generateAttempts.get(ip);
  if (!record) {
    generateAttempts.set(ip, { count: 1, lastAttempt: now });
    return false;
  }
  if (now - record.lastAttempt > GENERATE_RATE_WINDOW) {
    generateAttempts.set(ip, { count: 1, lastAttempt: now });
    return false;
  }
  record.count++;
  record.lastAttempt = now;
  return record.count > GENERATE_MAX_ATTEMPTS;
}

function clearRateLimit(ip: string): void {
  loginAttempts.delete(ip);
}

// ─── Auth Middleware ─────────────────────────────────────────────────
function requireAuth(request: Request): Response | null {
  if (!webPassword) return null;

  const clientIP = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || request.headers.get('cf-connecting-ip') || 'unknown';

  if (isRateLimited(clientIP)) {
    return new Response("Too Many Requests. Try again later.", {
      status: 429,
      headers: { "Content-Type": "text/plain" },
    });
  }

  const authHeader = request.headers.get("Authorization") || '';
  const expectedAuth = `Basic ${btoa(`${webUsername}:${webPassword}`)}`;

  if (!constantTimeEqual(authHeader, expectedAuth)) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="VLESS Proxy Admin"',
        "Content-Type": "text/plain",
      },
    });
  }

  clearRateLimit(clientIP);
  return null;
}

// ─── UUID Helpers ────────────────────────────────────────────────────
function maskUUID(uuid: string): string {
  if (uuid.length < 8) return '****';
  return uuid.slice(0, 4) + '****-****-****-****-********' + uuid.slice(-4);
}

function isValidUUID(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

// ─── Proxy IP Selection ──────────────────────────────────────────────
let fixedProxyIP = '';
if (stickyProxyIPEnv) {
  fixedProxyIP = stickyProxyIPEnv.trim();
  console.log(`Using STICKY_PROXYIP (forced): ${fixedProxyIP}`);
} else if (proxyIPs.length > 0) {
  fixedProxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
  console.log(`Selected fixed Proxy IP from list: ${fixedProxyIP} (will not change until restart)`);
}

function getFixedProxyIP(): string {
  return fixedProxyIP;
}

// ─── Config File ─────────────────────────────────────────────────────
async function getUUIDFromConfig(): Promise<string | undefined> {
  if (await exists(CONFIG_FILE)) {
    try {
      const configText = await Deno.readTextFile(CONFIG_FILE);
      const config: Config = JSON.parse(configText);
      if (config.uuid && isValidUUID(config.uuid)) {
        console.log(`Loaded UUID from ${CONFIG_FILE}: ${maskUUID(config.uuid)}`);
        return config.uuid;
      }
    } catch (e) {
      console.warn(`Error reading or parsing ${CONFIG_FILE}:`, (e as Error).message);
    }
  }
  return undefined;
}

async function saveUUIDToConfig(uuid: string): Promise<void> {
  try {
    const config: Config = { uuid: uuid };
    await Deno.writeTextFile(CONFIG_FILE, JSON.stringify(config, null, 2));
    console.log(`Saved new UUID to ${CONFIG_FILE}: ${maskUUID(uuid)}`);
  } catch (e) {
    console.error(`Failed to save UUID to ${CONFIG_FILE}:`, (e as Error).message);
  }
}

// ─── UUID Initialization ─────────────────────────────────────────────
let userIDs: string[] = [];
if (envUUID) {
  userIDs = envUUID.split(',').map(u => u.trim().toLowerCase()).filter(isValidUUID);
  if (userIDs.length > 0) {
    console.log(`Using UUIDs from environment: ${userIDs.map(maskUUID).join(', ')}`);
  }
}

if (userIDs.length === 0) {
  const configUUID = await getUUIDFromConfig();
  if (configUUID) {
    userIDs.push(configUUID.toLowerCase());
  } else {
    const newUUID = crypto.randomUUID();
    console.log(`Generated new UUID: ${maskUUID(newUUID)}`);
    await saveUUIDToConfig(newUUID);
    userIDs.push(newUUID);
  }
}

if (userIDs.length === 0) {
  throw new Error('No valid UUID available');
}

const primaryUserID = userIDs[0];
console.log(Deno.version);
console.log(`UUIDs in use: ${userIDs.map(maskUUID).join(', ')}`);
console.log(`WebSocket path: ${wsPath}`);
console.log(`Fixed Proxy IP: ${fixedProxyIP || '(none — direct connection)'}`);

// ─── Active Generated UUIDs (for VLESS auth) ────────────────────────
// We keep generated UUIDs in memory for fast auth checking
let activeGeneratedUUIDs: string[] = [];

async function refreshActiveUUIDs(): Promise<void> {
  const store = await loadKeysStore();
  activeGeneratedUUIDs = store.keys.map(k => k.uuid);
}

await refreshActiveUUIDs();

// Refresh periodically (every 5 minutes)
setInterval(async () => {
  await refreshActiveUUIDs();
}, 5 * 60 * 1000);

function getAllValidUUIDs(): string[] {
  return [...userIDs, ...activeGeneratedUUIDs];
}

// ─── Connection Tracking & Graceful Shutdown ─────────────────────────
const activeConnections = new Set<Deno.TcpConn>();
const CONNECTION_TIMEOUT = 10000;

function trackConnection(conn: Deno.TcpConn): void {
  activeConnections.add(conn);
}

function untrackConnection(conn: Deno.TcpConn): void {
  activeConnections.delete(conn);
}

try {
  Deno.addSignalListener("SIGINT", () => {
    console.log("SIGINT received, shutting down...");
    for (const conn of activeConnections) {
      try { conn.close(); } catch (_) { /* ignore */ }
    }
    Deno.exit(0);
  });
} catch (_) {
  // Signal listeners may not be available on all platforms
}

// ─── HTML Template (Updated with better UI) ──────────────────────────
const getHtml = (title: string, bodyContent: string, extraHead = '') => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHtml(title)}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0a0e1a;
            --card-bg: rgba(15, 23, 42, 0.8);
            --card-bg-hover: rgba(20, 30, 55, 0.9);
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --accent: #06b6d4;
            --accent2: #a78bfa;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --text-main: #f1f5f9;
            --text-sub: #94a3b8;
            --text-muted: #64748b;
            --border: rgba(148, 163, 184, 0.08);
            --border-light: rgba(148, 163, 184, 0.15);
            --glow-primary: rgba(99, 102, 241, 0.15);
            --glow-accent: rgba(6, 182, 212, 0.15);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-color);
            background-image:
                radial-gradient(ellipse at 10% 0%, rgba(99, 102, 241, 0.12) 0px, transparent 60%),
                radial-gradient(ellipse at 90% 100%, rgba(6, 182, 212, 0.08) 0px, transparent 60%),
                radial-gradient(ellipse at 50% 50%, rgba(167, 139, 250, 0.05) 0px, transparent 70%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            overflow-x: hidden;
        }

        .container {
            background: var(--card-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            padding: 48px 40px;
            border-radius: 28px;
            box-shadow:
                0 25px 60px -12px rgba(0, 0, 0, 0.6),
                0 0 0 1px rgba(255, 255, 255, 0.03) inset;
            max-width: 720px;
            width: 100%;
            text-align: center;
            animation: fadeIn 0.7s cubic-bezier(0.16, 1, 0.3, 1);
            position: relative;
        }

        .container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 60%;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(99, 102, 241, 0.5), rgba(6, 182, 212, 0.5), transparent);
        }

        .logo {
            width: 64px;
            height: 64px;
            margin: 0 auto 20px;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border-radius: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            box-shadow: 0 8px 32px rgba(99, 102, 241, 0.3);
        }

        h1 {
            font-size: 2.4rem;
            font-weight: 800;
            background: linear-gradient(135deg, #818cf8, #06b6d4, #a78bfa);
            background-size: 200% 200%;
            animation: gradientShift 5s ease infinite;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
            letter-spacing: -0.02em;
        }

        .subtitle {
            color: var(--text-sub);
            font-size: 1rem;
            line-height: 1.7;
            margin-bottom: 2rem;
            font-weight: 400;
        }

        /* Cycle Info Banner */
        .cycle-banner {
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(6, 182, 212, 0.1));
            border: 1px solid rgba(99, 102, 241, 0.2);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 28px;
            position: relative;
            overflow: hidden;
        }

        .cycle-banner::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 120px;
            height: 120px;
            background: radial-gradient(circle, rgba(99, 102, 241, 0.15), transparent 70%);
            border-radius: 50%;
            transform: translate(30%, -30%);
        }

        .cycle-status {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.25);
            color: #34d399;
            padding: 6px 16px;
            border-radius: 50px;
            font-size: 0.8rem;
            font-weight: 600;
            letter-spacing: 0.03em;
            margin-bottom: 16px;
        }

        .cycle-status .pulse {
            width: 8px;
            height: 8px;
            background: #34d399;
            border-radius: 50%;
            animation: pulse 2s ease-in-out infinite;
        }

        .cycle-dates {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;
        }

        .cycle-date-item {
            text-align: center;
        }

        .cycle-date-label {
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 4px;
        }

        .cycle-date-value {
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--text-main);
        }

        .cycle-arrow {
            color: var(--text-muted);
            font-size: 1.2rem;
        }

        /* Countdown */
        .countdown {
            display: flex;
            justify-content: center;
            gap: 14px;
            margin: 24px 0;
        }

        .countdown-item {
            background: rgba(10, 14, 26, 0.6);
            border: 1px solid var(--border-light);
            border-radius: 16px;
            padding: 18px 20px;
            min-width: 78px;
            transition: all 0.3s;
        }

        .countdown-item:hover {
            border-color: rgba(99, 102, 241, 0.3);
            box-shadow: 0 4px 20px rgba(99, 102, 241, 0.1);
        }

        .countdown-number {
            font-size: 2rem;
            font-weight: 800;
            background: linear-gradient(to bottom, #818cf8, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1;
            font-variant-numeric: tabular-nums;
        }

        .countdown-label {
            font-size: 0.65rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.12em;
            margin-top: 8px;
            font-weight: 500;
        }

        /* Time progress bar */
        .time-progress {
            margin: 20px 0;
        }

        .time-progress-bar {
            background: rgba(10, 14, 26, 0.6);
            border-radius: 10px;
            height: 8px;
            overflow: hidden;
            border: 1px solid var(--border);
        }

        .time-progress-fill {
            height: 100%;
            border-radius: 10px;
            background: linear-gradient(90deg, #6366f1, #06b6d4, #a78bfa);
            background-size: 200% 100%;
            animation: shimmer 3s linear infinite;
            transition: width 1s ease;
        }

        .time-progress-text {
            display: flex;
            justify-content: space-between;
            margin-top: 8px;
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        /* Generate Button */
        .generate-section {
            margin: 32px 0;
        }

        .btn-generate {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            background: linear-gradient(135deg, #6366f1, #4f46e5);
            color: white;
            padding: 16px 48px;
            border-radius: 16px;
            text-decoration: none;
            font-weight: 700;
            font-size: 1.05rem;
            transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            box-shadow: 0 8px 32px rgba(99, 102, 241, 0.35);
            border: none;
            cursor: pointer;
            letter-spacing: 0.01em;
            position: relative;
            overflow: hidden;
        }

        .btn-generate::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent);
            transition: left 0.5s;
        }

        .btn-generate:hover::before {
            left: 100%;
        }

        .btn-generate:hover {
            transform: translateY(-3px);
            box-shadow: 0 16px 48px rgba(99, 102, 241, 0.45);
        }

        .btn-generate:active {
            transform: translateY(-1px);
        }

        .btn-generate:disabled {
            background: #334155;
            box-shadow: none;
            cursor: not-allowed;
            transform: none;
        }

        .btn-generate:disabled::before { display: none; }

        .btn-generate .icon {
            font-size: 1.2rem;
        }

        /* Result Card */
        .result-card {
            background: rgba(10, 14, 26, 0.5);
            border: 1px solid var(--border-light);
            border-radius: 20px;
            padding: 28px 24px;
            margin-top: 24px;
            text-align: left;
            animation: slideUp 0.5s cubic-bezier(0.16, 1, 0.3, 1);
            display: none;
        }

        .result-card.show { display: block; }

        .result-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 20px;
        }

        .result-icon {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.2), rgba(6, 182, 212, 0.2));
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.3rem;
        }

        .result-title {
            font-weight: 700;
            font-size: 1.05rem;
            color: var(--text-main);
        }

        .result-subtitle {
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        .config-box {
            background: rgba(10, 14, 26, 0.7);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 18px;
            margin-top: 16px;
            position: relative;
        }

        .config-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }

        .config-title {
            font-weight: 600;
            color: #cbd5e1;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }

        .config-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            font-size: 0.7rem;
            padding: 3px 10px;
            border-radius: 6px;
        }

        .badge-vless {
            background: rgba(99, 102, 241, 0.1);
            color: #818cf8;
            border: 1px solid rgba(99, 102, 241, 0.2);
        }

        .badge-clash {
            background: rgba(245, 158, 11, 0.1);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.2);
        }

        pre {
            margin: 0;
            white-space: pre-wrap;
            word-break: break-all;
            font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
            font-size: 0.82rem;
            color: #94a3b8;
            max-height: 120px;
            overflow-y: auto;
            padding-right: 8px;
            line-height: 1.6;
        }

        pre::-webkit-scrollbar { width: 5px; }
        pre::-webkit-scrollbar-track { background: transparent; }
        pre::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }

        .copy-btn {
            background: rgba(99, 102, 241, 0.08);
            color: #818cf8;
            border: 1px solid rgba(99, 102, 241, 0.2);
            padding: 7px 16px;
            border-radius: 8px;
            font-size: 0.78rem;
            cursor: pointer;
            transition: all 0.2s;
            font-weight: 500;
            font-family: inherit;
        }

        .copy-btn:hover {
            background: rgba(99, 102, 241, 0.15);
            border-color: rgba(99, 102, 241, 0.4);
        }

        /* Feature Grid */
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 14px;
            margin: 28px 0;
        }

        .feature-item {
            background: rgba(10, 14, 26, 0.4);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 22px 14px;
            transition: all 0.3s;
        }

        .feature-item:hover {
            border-color: rgba(99, 102, 241, 0.2);
            background: rgba(10, 14, 26, 0.6);
            transform: translateY(-2px);
        }

        .feature-icon { font-size: 1.6rem; margin-bottom: 10px; }
        .feature-name {
            font-size: 0.82rem;
            color: var(--text-sub);
            font-weight: 500;
        }

        /* Stats */
        .stats-row {
            display: flex;
            justify-content: center;
            gap: 32px;
            margin: 20px 0;
        }

        .stat-item { text-align: center; }

        .stat-number {
            font-size: 1.8rem;
            font-weight: 800;
            background: linear-gradient(to bottom, #818cf8, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .stat-label {
            font-size: 0.72rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-top: 2px;
        }

        /* Footer */
        .footer {
            margin-top: 36px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        .footer a {
            color: var(--text-sub);
            text-decoration: none;
            transition: color 0.2s;
        }

        .footer a:hover { color: var(--primary); }

        /* Toast */
        .toast {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid rgba(16, 185, 129, 0.25);
            color: #34d399;
            padding: 14px 28px;
            border-radius: 14px;
            font-size: 0.88rem;
            font-weight: 500;
            transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);
            backdrop-filter: blur(12px);
            z-index: 100;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }

        .toast.show { transform: translateX(-50%) translateY(0); }

        .toast.error {
            border-color: rgba(239, 68, 68, 0.25);
            color: #f87171;
        }

        /* Spinner */
        .spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2.5px solid rgba(255,255,255,0.2);
            border-top-color: white;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        /* User Section (for admin /config) */
        .user-section {
            border-top: 1px solid var(--border);
            margin-top: 28px;
            padding-top: 24px;
        }

        .user-label {
            display: inline-block;
            background: rgba(99, 102, 241, 0.1);
            color: #818cf8;
            padding: 5px 14px;
            border-radius: 20px;
            font-size: 0.78rem;
            font-weight: 600;
            margin-bottom: 12px;
            border: 1px solid rgba(99, 102, 241, 0.2);
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: var(--primary);
            color: white;
            padding: 12px 30px;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.2s;
            box-shadow: 0 4px 6px -1px rgba(99, 102, 241, 0.4);
            border: none;
            cursor: pointer;
            font-size: 1rem;
            margin: 5px;
        }

        .btn:hover {
            background: var(--primary-hover);
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(99, 102, 241, 0.4);
        }

        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(24px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(16px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes gradientShift {
            0%, 100% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(0.8); }
        }

        @keyframes shimmer {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @media (max-width: 600px) {
            .container { padding: 32px 20px; border-radius: 20px; }
            h1 { font-size: 1.7rem; }
            .countdown { gap: 8px; }
            .countdown-item { padding: 14px 14px; min-width: 64px; }
            .countdown-number { font-size: 1.5rem; }
            .feature-grid { grid-template-columns: repeat(3, 1fr); gap: 8px; }
            .feature-item { padding: 16px 8px; }
            .btn-generate { padding: 14px 36px; font-size: 0.95rem; }
            .stats-row { gap: 20px; }
            .cycle-dates { gap: 10px; }
        }

        ${extraHead}
    </style>
</head>
<body>
    <div class="container">
        ${bodyContent}
    </div>
    <div class="toast" id="toast"></div>
    <script>
        function showToast(msg, isError = false) {
            const t = document.getElementById('toast');
            t.textContent = msg;
            t.className = isError ? 'toast error show' : 'toast show';
            setTimeout(() => { t.className = t.className.replace(' show', ''); }, 3000);
        }

        function copyToClipboard(elementId, btn) {
            const text = document.getElementById(elementId).innerText;
            navigator.clipboard.writeText(text).then(() => {
                const orig = btn.innerText;
                btn.innerText = 'Copied!';
                btn.style.background = 'rgba(16, 185, 129, 0.1)';
                btn.style.color = '#34d399';
                btn.style.borderColor = 'rgba(16, 185, 129, 0.3)';
                showToast('Copied to clipboard!');
                setTimeout(() => { btn.innerText = orig; btn.style = ''; }, 2000);
            }).catch(() => showToast('Failed to copy', true));
        }
    </script>
</body>
</html>
`;

// ─── Connection with Timeout ─────────────────────────────────────────
async function connectWithTimeout(hostname: string, port: number, timeout: number): Promise<Deno.TcpConn> {
  let timeoutId: number;
  const connPromise = Deno.connect({ hostname, port });
  const timer = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(
      () => reject(new Error(`Connection to ${hostname}:${port} timed out after ${timeout}ms`)),
      timeout
    );
  });
  try {
    const result = await Promise.race([connPromise, timer]);
    clearTimeout(timeoutId!);
    return result;
  } catch (e) {
    clearTimeout(timeoutId!);
    connPromise.then(c => { try { c.close(); } catch (_) { /* ignore */ } }).catch(() => {});
    throw e;
  }
}

// ─── Helper: Check if error is a normal disconnect ───────────────────
function isNormalDisconnectError(error: unknown): boolean {
  if (error instanceof Error) {
    const err = error as Error & { code?: string; name?: string };
    return (
      err.code === 'EINTR' ||
      err.name === 'Interrupted' ||
      err.name === 'AbortError' ||
      err.message?.includes('operation canceled') ||
      err.message?.includes('connection reset') ||
      err.message?.includes('broken pipe')
    );
  }
  return false;
}

// ─── Main Server ─────────────────────────────────────────────────────
Deno.serve(async (request: Request) => {
  const upgrade = request.headers.get('upgrade') || '';
  if (upgrade.toLowerCase() === 'websocket') {
    const url = new URL(request.url);
    if (url.pathname !== wsPath) {
      return new Response('Not Found', { status: 404 });
    }
    return await vlessOverWSHandler(request);
  }

  const url = new URL(request.url);

  // ── Health ──
  if (url.pathname === '/health') {
    return new Response(JSON.stringify({
      status: 'ok',
      timestamp: new Date().toISOString(),
    }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // ── Protected routes: /sub and /config ──
  if (url.pathname === '/sub' || url.pathname === '/config') {
    const authResponse = requireAuth(request);
    if (authResponse) return authResponse;
  }

  if (url.pathname === '/sub') {
    const hostName = url.hostname;
    const port = url.port || (url.protocol === 'https:' ? 443 : 80);

    // Include all UUIDs (original + generated active ones)
    const store = await loadKeysStore();
    const allUUIDs = [...userIDs, ...store.keys.map(k => k.uuid)];

    const allLinks = allUUIDs.map((uid, index) => {
      const tag = credit ? `${credit}-${index + 1}` : `${hostName}-${index + 1}`;
      return `vless://${uid}@${hostName}:${port}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=${encodeURIComponent(wsPath + '?ed=2048')}#${tag}`;
    }).join('\n');
    const base64Content = btoa(allLinks);
    return new Response(base64Content, {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Profile-Update-Interval': '12',
        'Subscription-Userinfo': 'upload=0; download=0; total=10737418240; expire=0',
      },
    });
  }

  // ── API: Generate Key ──
  if (url.pathname === '/api/generate' && request.method === 'POST') {
    const clientIP = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
      || request.headers.get('cf-connecting-ip') || 'unknown';

    if (isGenerateRateLimited(clientIP)) {
      return new Response(JSON.stringify({ error: 'Too many requests. Please wait a moment.' }), {
        status: 429,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const hostName = url.hostname;
    const port = url.port || (url.protocol === 'https:' ? 443 : 80);

    const newUUID = crypto.randomUUID();
    const now = new Date();
    const cycleEnd = getCurrentCycleEnd();

    const tag = credit ? `${credit}-gen` : `${hostName}-gen`;
    const vlessLink = `vless://${newUUID}@${hostName}:${port}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=${encodeURIComponent(wsPath + '?ed=2048')}#${tag}`;

    const key: GeneratedKey = {
      id: crypto.randomUUID().slice(0, 8),
      uuid: newUUID,
      vlessKey: vlessLink,
      createdAt: now.toISOString(),
      cycleStart: formatDate(getCurrentCycleStart()),
      cycleEnd: formatDate(cycleEnd),
    };

    const store = await loadKeysStore();
    store.keys.push(key);
    await saveKeysStore(store);

    // Refresh active UUIDs
    activeGeneratedUUIDs.push(newUUID);

    const clashConfig = `- type: vless
  name: ${tag}
  server: ${hostName}
  port: ${port}
  uuid: ${newUUID}
  network: ws
  tls: true
  udp: false
  sni: ${hostName}
  client-fingerprint: chrome
  ws-opts:
    path: "${wsPath}?ed=2048"
    headers:
      host: ${hostName}`;

    return new Response(JSON.stringify({
      success: true,
      vlessKey: vlessLink,
      clashConfig: clashConfig,
      expiresAt: cycleEnd.toISOString(),
      expiresAtReadable: formatDateReadable(cycleEnd),
      cycleStart: formatDate(getCurrentCycleStart()),
      cycleEnd: formatDate(cycleEnd),
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // ── API: Get Cycle Info ──
  if (url.pathname === '/api/cycle-info') {
    const cycleStart = getCurrentCycleStart();
    const cycleEnd = getCurrentCycleEnd();
    const now = new Date();
    const totalMs = cycleEnd.getTime() - cycleStart.getTime();
    const elapsedMs = now.getTime() - cycleStart.getTime();
    const progress = Math.min(100, Math.max(0, (elapsedMs / totalMs) * 100));

    return new Response(JSON.stringify({
      cycleStart: cycleStart.toISOString(),
      cycleEnd: cycleEnd.toISOString(),
      cycleStartReadable: formatDateReadable(cycleStart),
      cycleEndReadable: formatDateReadable(cycleEnd),
      progress: Math.round(progress * 100) / 100,
      remainingMs: cycleEnd.getTime() - now.getTime(),
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  switch (url.pathname) {
    case '/': {
      const cycleStart = getCurrentCycleStart();
      const cycleEnd = getCurrentCycleEnd();

      const content = `
          <div class="logo">⚡</div>
          <h1>${escapeHtml(credit || 'VPN Key Generator')}</h1>
          <p class="subtitle">Generate your personal VLESS key instantly. Each key is valid until the weekly reset.</p>

          <div class="cycle-banner">
              <div class="cycle-status">
                  <span class="pulse"></span>
                  <span>ACTIVE CYCLE</span>
              </div>
              <div class="cycle-dates">
                  <div class="cycle-date-item">
                      <div class="cycle-date-label">Started</div>
                      <div class="cycle-date-value" id="cycle-start">${escapeHtml(formatDateReadable(cycleStart))}</div>
                  </div>
                  <div class="cycle-arrow">→</div>
                  <div class="cycle-date-item">
                      <div class="cycle-date-label">Expires</div>
                      <div class="cycle-date-value" id="cycle-end">${escapeHtml(formatDateReadable(cycleEnd))}</div>
                  </div>
              </div>
          </div>

          <div class="countdown" id="countdown">
              <div class="countdown-item">
                  <div class="countdown-number" id="days">--</div>
                  <div class="countdown-label">Days</div>
              </div>
              <div class="countdown-item">
                  <div class="countdown-number" id="hours">--</div>
                  <div class="countdown-label">Hours</div>
              </div>
              <div class="countdown-item">
                  <div class="countdown-number" id="minutes">--</div>
                  <div class="countdown-label">Min</div>
              </div>
              <div class="countdown-item">
                  <div class="countdown-number" id="seconds">--</div>
                  <div class="countdown-label">Sec</div>
              </div>
          </div>

          <div class="time-progress">
              <div class="time-progress-bar">
                  <div class="time-progress-fill" id="progress-fill" style="width: 0%"></div>
              </div>
              <div class="time-progress-text">
                  <span id="progress-elapsed">Loading...</span>
                  <span id="progress-remaining">Loading...</span>
              </div>
          </div>

          <div class="generate-section">
              <button class="btn-generate" id="generateBtn" onclick="generateKey()">
                  <span class="icon">⚡</span>
                  <span id="btnText">Generate VLESS Key</span>
              </button>
          </div>

          <div class="result-card" id="resultCard">
              <div class="result-header">
                  <div class="result-icon">✅</div>
                  <div>
                      <div class="result-title">Your Key is Ready!</div>
                      <div class="result-subtitle">Valid until <span id="result-expiry"></span></div>
                  </div>
              </div>

              <div class="config-box">
                  <div class="config-header">
                      <div style="display:flex;align-items:center;gap:8px;">
                          <span class="config-title">VLESS URI</span>
                          <span class="config-badge badge-vless">V2RayNG / v2rayN</span>
                      </div>
                      <button class="copy-btn" onclick="copyToClipboard('vless-result', this)">Copy</button>
                  </div>
                  <pre id="vless-result"></pre>
              </div>

              <div class="config-box">
                  <div class="config-header">
                      <div style="display:flex;align-items:center;gap:8px;">
                          <span class="config-title">Clash Meta</span>
                          <span class="config-badge badge-clash">YAML</span>
                      </div>
                      <button class="copy-btn" onclick="copyToClipboard('clash-result', this)">Copy</button>
                  </div>
                  <pre id="clash-result"></pre>
              </div>
          </div>

          <div class="feature-grid">
              <div class="feature-item">
                  <div class="feature-icon">⚡</div>
                  <div class="feature-name">Fast & Secure</div>
              </div>
              <div class="feature-item">
                  <div class="feature-icon">🔄</div>
                  <div class="feature-name">Weekly Reset</div>
              </div>
              <div class="feature-item">
                  <div class="feature-icon">🌍</div>
                  <div class="feature-name">Global Access</div>
              </div>
          </div>

          <div class="footer">
              <p>&copy; 2026 ${escapeHtml(credit || 'VPN Service')}. Keys reset every week automatically.</p>
          </div>

          <script>
              const cycleEndISO = "${cycleEnd.toISOString()}";
              const cycleStartISO = "${cycleStart.toISOString()}";
              const cycleEndDate = new Date(cycleEndISO);
              const cycleStartDate = new Date(cycleStartISO);
              const totalCycleMs = cycleEndDate.getTime() - cycleStartDate.getTime();

              function updateCountdown() {
                  const now = new Date();
                  let diff = cycleEndDate.getTime() - now.getTime();
                  if (diff < 0) {
                      // Cycle expired, reload page to get new cycle
                      location.reload();
                      return;
                  }
                  const d = Math.floor(diff / (1000 * 60 * 60 * 24));
                  const h = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                  const m = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                  const s = Math.floor((diff % (1000 * 60)) / 1000);
                  document.getElementById('days').textContent = String(d).padStart(2, '0');
                  document.getElementById('hours').textContent = String(h).padStart(2, '0');
                  document.getElementById('minutes').textContent = String(m).padStart(2, '0');
                  document.getElementById('seconds').textContent = String(s).padStart(2, '0');

                  // Progress
                  const elapsed = now.getTime() - cycleStartDate.getTime();
                  const progress = Math.min(100, Math.max(0, (elapsed / totalCycleMs) * 100));
                  document.getElementById('progress-fill').style.width = progress.toFixed(1) + '%';

                  const elapsedDays = Math.floor(elapsed / (1000 * 60 * 60 * 24));
                  const remainDays = Math.ceil(diff / (1000 * 60 * 60 * 24));
                  document.getElementById('progress-elapsed').textContent = 'Day ' + (elapsedDays + 1) + ' of 7';
                  document.getElementById('progress-remaining').textContent = remainDays + ' day' + (remainDays !== 1 ? 's' : '') + ' remaining';
              }

              updateCountdown();
              setInterval(updateCountdown, 1000);

              let isGenerating = false;

              async function generateKey() {
                  if (isGenerating) return;
                  isGenerating = true;
                  const btn = document.getElementById('generateBtn');
                  const btnText = document.getElementById('btnText');
                  btn.disabled = true;
                  btnText.innerHTML = '<span class="spinner"></span> Generating...';

                  try {
                      const res = await fetch('/api/generate', { method: 'POST' });
                      const data = await res.json();

                      if (!res.ok) {
                          showToast(data.error || 'Failed to generate key', true);
                          return;
                      }

                      document.getElementById('vless-result').textContent = data.vlessKey;
                      document.getElementById('clash-result').textContent = data.clashConfig;
                      document.getElementById('result-expiry').textContent = data.expiresAtReadable;
                      document.getElementById('resultCard').classList.add('show');
                      showToast('Key generated successfully!');

                      // Scroll to result
                      setTimeout(() => {
                          document.getElementById('resultCard').scrollIntoView({ behavior: 'smooth', block: 'center' });
                      }, 200);

                  } catch (err) {
                      showToast('Network error. Please try again.', true);
                  } finally {
                      isGenerating = false;
                      btn.disabled = false;
                      btnText.innerHTML = '<span class="icon">⚡</span> Generate Another Key';
                  }
              }
          </script>
      `;
      return new Response(getHtml(credit || 'VPN Key Generator', content), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    case '/config': {
      const hostName = url.hostname;
      const port = url.port || (url.protocol === 'https:' ? 443 : 80);
      const store = await loadKeysStore();
      let userSections = '';

      // Show original server UUIDs
      userIDs.forEach((uid, index) => {
        const rawTag = credit ? `${credit}-${index + 1}` : `${hostName}-${index + 1}`;
        const vlessLink = `vless://${uid}@${hostName}:${port}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=${encodeURIComponent(wsPath + '?ed=2048')}#${rawTag}`;

        const clashConfig = `
- type: vless
  name: ${rawTag}
  server: ${hostName}
  port: ${port}
  uuid: ${uid}
  network: ws
  tls: true
  udp: false
  sni: ${hostName}
  client-fingerprint: chrome
  ws-opts:
    path: "${wsPath}?ed=2048"
    headers:
      host: ${hostName}`;

        userSections += `
          <div class="${index > 0 ? 'user-section' : ''}">
              <span class="user-label">Server UUID ${index + 1}</span>
              <div class="config-box">
                  <div class="config-header">
                      <span class="config-title">VLESS URI</span>
                      <button class="copy-btn" onclick="copyToClipboard('vless-uri-${index}', this)">Copy</button>
                  </div>
                  <pre id="vless-uri-${index}">${escapeHtml(vlessLink)}</pre>
              </div>
              <div class="config-box">
                  <div class="config-header">
                      <span class="config-title">Clash Meta YAML</span>
                      <button class="copy-btn" onclick="copyToClipboard('clash-config-${index}', this)">Copy</button>
                  </div>
                  <pre id="clash-config-${index}">${escapeHtml(clashConfig.trim())}</pre>
              </div>
          </div>
        `;
      });

      // Show generated keys info
      if (store.keys.length > 0) {
        userSections += `
          <div class="user-section">
              <span class="user-label">Generated Keys (${store.keys.length}) — Cycle: ${escapeHtml(store.currentCycleStart)} → ${escapeHtml(store.currentCycleEnd)}</span>
              <div class="config-box">
                  <div class="config-header">
                      <span class="config-title">Active Generated Keys</span>
                  </div>
                  <pre>${store.keys.map((k, i) => `#${i + 1} | ID: ${k.id} | Created: ${k.createdAt.split('T')[0]} | UUID: ${maskUUID(k.uuid)}`).join('\n')}</pre>
              </div>
          </div>
        `;
      }

      const content = `
          <div class="logo">🔧</div>
          <h1>Admin Configuration</h1>
          <p class="subtitle">Server UUIDs and generated keys management.</p>

          <div class="stats-row">
              <div class="stat-item">
                  <div class="stat-number">${userIDs.length}</div>
                  <div class="stat-label">Server UUIDs</div>
              </div>
              <div class="stat-item">
                  <div class="stat-number">${store.keys.length}</div>
                  <div class="stat-label">Generated Keys</div>
              </div>
              <div class="stat-item">
                  <div class="stat-number">${CYCLE_DURATION_DAYS}d</div>
                  <div class="stat-label">Cycle Length</div>
              </div>
          </div>

          ${userSections}

          <div class="config-box" style="margin-top: 30px;">
              <div class="config-header">
                  <span class="config-title">Subscription URL</span>
                  <button class="copy-btn" onclick="copyToClipboard('sub-url', this)">Copy</button>
              </div>
              <pre id="sub-url">https://${escapeHtml(url.hostname)}/sub</pre>
          </div>

          <div class="footer">
              <a href="/">← Back to Home</a>
          </div>
      `;
      return new Response(getHtml('Admin Config', content), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    default:
      return new Response(getHtml('404', `
        <div class="logo">🔍</div>
        <h1>404</h1>
        <p class="subtitle">The page you're looking for doesn't exist.</p>
        <a href="/" class="btn">Go Home</a>
      `), {
        status: 404,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
  }
});

// ─── VLESS over WebSocket Handler ────────────────────────────────────
async function vlessOverWSHandler(request: Request) {
  const { socket, response } = Deno.upgradeWebSocket(request);

  let address = '';
  let portWithRandomLog = '';
  const log = (info: string, event = '') => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event);
  };

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(socket, earlyDataHeader, log);

  const remoteSocketWrapper: { value: Deno.TcpConn | null } = {
    value: null,
  };
  let udpStreamWrite: ((chunk: Uint8Array) => void) | null = null;
  let isDns = false;

  const cleanupRemote = () => {
    safeCloseRemote(remoteSocketWrapper.value);
    remoteSocketWrapper.value = null;
  };

  socket.addEventListener('close', () => {
    log('WebSocket closed by client');
    cleanupRemote();
  });

  socket.addEventListener('error', (e) => {
    log('WebSocket error', String(e));
    cleanupRemote();
  });

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            try {
              await writer.write(new Uint8Array(chunk));
            } finally {
              writer.releaseLock();
            }
            return;
          }

          // Use ALL valid UUIDs (original + generated active ones)
          const allValidIDs = getAllValidUUIDs();

          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = '',
            rawDataIndex,
            vlessVersion = new Uint8Array([0, 0]),
            isUDP,
          } = processVlessHeader(chunk, allValidIDs);

          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;

          if (hasError) {
            throw new Error(message);
          }

          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
            } else {
              throw new Error('UDP proxy only enabled for DNS which is port 53');
            }
          }

          const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isDns) {
            console.log('isDns:', isDns);
            const { write } = await handleUDPOutBound(socket, vlessResponseHeader, log);
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }

          handleTCPOutBound(
            remoteSocketWrapper,
            addressRemote,
            portRemote,
            rawClientData,
            socket,
            vlessResponseHeader,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is closed`);
          cleanupRemote();
        },
        abort(reason) {
          log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
          cleanupRemote();
        },
      })
    )
    .catch((err) => {
      if (isNormalDisconnectError(err)) {
        log('WebSocket stream ended (client disconnected)');
      } else {
        log('readableWebSocketStream pipeTo error', String(err));
      }
      cleanupRemote();
      safeCloseWebSocket(socket);
    });

  return response;
}

// ─── Safe Close Remote TCP ───────────────────────────────────────────
function safeCloseRemote(conn: Deno.TcpConn | null): void {
  if (conn) {
    untrackConnection(conn);
    try { conn.close(); } catch (_) { /* ignore */ }
  }
}

// ─── TCP Outbound Handler ────────────────────────────────────────────
async function handleTCPOutBound(
  remoteSocket: { value: Deno.TcpConn | null },
  addressRemote: string,
  portRemote: number,
  rawClientData: Uint8Array,
  webSocket: WebSocket,
  vlessResponseHeader: Uint8Array,
  log: (info: string, event?: string) => void
) {
  async function connectAndWrite(address: string, port: number) {
    try {
      const tcpSocket = await connectWithTimeout(address, port, CONNECTION_TIMEOUT);
      remoteSocket.value = tcpSocket;
      trackConnection(tcpSocket);
      log(`connected to ${address}:${port}`);
      const writer = tcpSocket.writable.getWriter();
      try {
        await writer.write(new Uint8Array(rawClientData));
      } finally {
        writer.releaseLock();
      }
      return tcpSocket;
    } catch (e) {
      log(`Failed to connect to ${address}:${port}: ${(e as Error).message}`);
      throw e;
    }
  }

  async function retry() {
    try {
      const fallbackIP = getFixedProxyIP();
      if (!fallbackIP) {
        log('No proxy IP available for retry');
        safeCloseWebSocket(webSocket);
        return;
      }
      log(`Retrying with fixed proxy IP: ${fallbackIP}`);
      const tcpSocket = await connectAndWrite(fallbackIP, portRemote);
      remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
    } catch (e) {
      log(`Retry failed: ${(e as Error).message}`);
      safeCloseWebSocket(webSocket);
    }
  }

  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
  } catch (e) {
    log(`Initial connection failed: ${(e as Error).message}, attempting retry...`);
    await retry();
  }
}

// ─── Readable WebSocket Stream ───────────────────────────────────────
function makeReadableWebSocketStream(
  webSocketServer: WebSocket,
  earlyDataHeader: string,
  log: (info: string, event?: string) => void
) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (readableStreamCancel) return;
        const data = event.data;
        if (data instanceof ArrayBuffer) {
          controller.enqueue(data);
        } else if (data instanceof Blob) {
          data.arrayBuffer().then(buf => {
            if (!readableStreamCancel) controller.enqueue(buf);
          }).catch(err => {
            log('Blob to ArrayBuffer error', String(err));
          });
        }
      });

      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) return;
        try {
          controller.close();
        } catch (_) { /* stream may already be closed */ }
      });

      webSocketServer.addEventListener('error', (err) => {
        log('webSocketServer has error');
        try {
          controller.error(err);
        } catch (_) { /* stream may already be errored */ }
      });

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(_controller) {},
    cancel(reason) {
      if (readableStreamCancel) return;
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
  return stream;
}

// ─── VLESS Header Parser ─────────────────────────────────────────────
function processVlessHeader(vlessBuffer: ArrayBuffer, validUserIDs: string[]) {
  if (vlessBuffer.byteLength < 24) {
    return { hasError: true, message: 'invalid data' };
  }

  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  const incomingUUID = stringify(new Uint8Array(vlessBuffer.slice(1, 17))).toLowerCase();

  let isValidUser = false;
  for (const id of validUserIDs) {
    if (constantTimeEqual(id, incomingUUID)) {
      isValidUser = true;
    }
  }

  if (!isValidUser) {
    return { hasError: true, message: 'invalid user' };
  }

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];

  if (18 + optLength + 1 > vlessBuffer.byteLength) {
    return { hasError: true, message: 'invalid header: optLength exceeds buffer' };
  }

  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
  let isUDP = false;

  if (command === 1) {
    // TCP
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} is not supported, command 01-tcp, 02-udp, 03-mux`,
    };
  }

  const portIndex = 18 + optLength + 1;

  if (portIndex + 2 > vlessBuffer.byteLength) {
    return { hasError: true, message: 'invalid header: buffer too short for port' };
  }

  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  const addressIndex = portIndex + 2;

  if (addressIndex + 1 > vlessBuffer.byteLength) {
    return { hasError: true, message: 'invalid header: buffer too short for address type' };
  }

  const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = '';

  switch (addressType) {
    case 1: {
      addressLength = 4;
      if (addressValueIndex + addressLength > vlessBuffer.byteLength) {
        return { hasError: true, message: 'invalid header: buffer too short for IPv4 address' };
      }
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
      break;
    }
    case 2: {
      if (addressValueIndex + 1 > vlessBuffer.byteLength) {
        return { hasError: true, message: 'invalid header: buffer too short for domain length' };
      }
      addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      if (addressValueIndex + addressLength > vlessBuffer.byteLength) {
        return { hasError: true, message: 'invalid header: domain length exceeds buffer' };
      }
      addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    }
    case 3: {
      addressLength = 16;
      if (addressValueIndex + addressLength > vlessBuffer.byteLength) {
        return { hasError: true, message: 'invalid header: buffer too short for IPv6 address' };
      }
      const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6: string[] = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(':');
      break;
    }
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

// ─── Remote Socket to WebSocket ──────────────────────────────────────
async function remoteSocketToWS(
  remoteSocket: Deno.TcpConn,
  webSocket: WebSocket,
  vlessResponseHeader: Uint8Array,
  retry: (() => Promise<void>) | null,
  log: (info: string, event?: string) => void
) {
  let hasIncomingData = false;
  let headerSent = false;

  const abortController = new AbortController();

  const onWsClose = () => {
    abortController.abort();
  };

  webSocket.addEventListener('close', onWsClose);
  webSocket.addEventListener('error', onWsClose);

  try {
    await remoteSocket.readable
      .pipeTo(
        new WritableStream({
          start() {},
          async write(chunk, controller) {
            hasIncomingData = true;

            if (webSocket.readyState !== WS_READY_STATE_OPEN) {
              controller.error('webSocket is closed');
              return;
            }

            try {
              if (!headerSent) {
                webSocket.send(new Uint8Array([...vlessResponseHeader, ...chunk]));
                headerSent = true;
              } else {
                webSocket.send(chunk);
              }
            } catch (e) {
              controller.error('WebSocket send failed: ' + (e as Error).message);
            }
          },
          close() {
            log(`remoteConnection!.readable is closed with hasIncomingData is ${hasIncomingData}`);
          },
          abort(reason) {
            if (isNormalDisconnectError(reason)) {
              log('Remote read ended (client disconnected)');
            } else {
              console.error('remoteConnection!.readable abort', reason);
            }
          },
        }),
        { signal: abortController.signal }
      );
  } catch (error) {
    if (isNormalDisconnectError(error)) {
      log('Connection ended normally (client disconnected)');
    } else {
      console.error('remoteSocketToWS has exception', (error as Error).stack || error);
    }
    safeCloseRemote(remoteSocket);
    safeCloseWebSocket(webSocket);
  } finally {
    try {
      webSocket.removeEventListener('close', onWsClose);
      webSocket.removeEventListener('error', onWsClose);
    } catch (_) { /* ignore */ }
  }

  if (hasIncomingData === false && retry) {
    log(`retry`);
    await retry();
  }
}

// ─── Base64 Decoder ──────────────────────────────────────────────────
function base64ToArrayBuffer(base64Str: string) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error: error };
  }
}

// ─── WebSocket Helpers ───────────────────────────────────────────────
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket: WebSocket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error', error);
  }
}

// ─── UUID Byte-to-Hex ────────────────────────────────────────────────
const byteToHex: string[] = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr: Uint8Array, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    '-' +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    '-' +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    '-' +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    '-' +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr: Uint8Array, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw TypeError('Stringified UUID is invalid');
  }
  return uuid;
}

// ─── UDP Outbound (DNS only) ─────────────────────────────────────────
async function handleUDPOutBound(
  webSocket: WebSocket,
  vlessResponseHeader: Uint8Array,
  log: (info: string) => void
) {
  let isVlessHeaderSent = false;

  const transformStream = new TransformStream({
    start(_controller) {},
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        if (index + 2 > chunk.byteLength) {
          console.error('UDP: not enough data for length header');
          break;
        }
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        if (udpPacketLength === 0 || index + 2 + udpPacketLength > chunk.byteLength) {
          console.error('UDP: invalid packet length or exceeds buffer');
          break;
        }
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
    flush(_controller) {},
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch('https://1.1.1.1/dns-query', {
            method: 'POST',
            headers: { 'content-type': 'application/dns-message' },
            body: chunk,
          });
          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            log(`doh success and dns message length is ${udpSize}`);
            if (isVlessHeaderSent) {
              webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            } else {
              webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              isVlessHeaderSent = true;
            }
          }
        },
      })
    )
    .catch((error) => {
      log('dns udp has error: ' + error);
    });

  const writer = transformStream.writable.getWriter();
  return {
    write(chunk: Uint8Array) {
      writer.write(chunk);
    },
  };
}
