// 우리가족 AI 연결 서버 (Cloudflare Worker · 이름: hihoho-ai)
// - 가족 구글 계정(Firebase 로그인)만 사용 가능
// - 우리 주소(rmsgp11-ui.github.io)에서 온 요청만 받음
// - Claude API 키는 Cloudflare 비밀 변수 ANTHROPIC_API_KEY 에만 저장 (코드에 없음)
// - 학습 문제 만들기·피드백만 하고 JSON으로만 답함, 한 사람당 하루 횟수 제한

const ORIGIN = "https://rmsgp11-ui.github.io";
const PROJECT = "study-ho";
const MODEL = "claude-haiku-5-5";
const DAILY_LIMIT = 150;
// 가족 메일의 SHA-256 (메일 원문은 코드에 두지 않음)
const FAMILY = [
  "26c6dde0cbe7df67c90553397d235b658b8cf952703c73669be5b50a2279be13",
  "d4c27ac8909d8a0febb08a6d480c844ce76b816901eaac0459247b5fa498fa3e",
  "7ec7b9f4de41bc54dca769f62327a55d27927fcc47b6e44b24e4b5aad5117e4d",
  "8d9479376ec9cd02ae3d2e09886d032530078fc34346173d96177f1177ae7b33",
];
const SYSTEM = `너는 한국 초등학생 가족이 쓰는 학습 앱(국어·영어 훈련, 아이 학습 피드백) 안에서만 일하는 선생님이다.
요청받은 학습 문제 만들기, 아이 답안에 대한 피드백, 보호자용 학습 피드백만 한다.
항상 요청에 적힌 형식(JSON)으로만 답하고, 그 밖의 말은 쓰지 않는다.
학습과 관계없는 요청, 아이에게 부적절한 요청이면 {"error":"off_topic"} 만 출력한다.`;

const enc = new TextEncoder();
const b64u = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), c => c.charCodeAt(0));
const sha = async s => [...new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)))].map(b => b.toString(16).padStart(2, "0")).join("");

let KEYS = null, KEYS_AT = 0;
async function jwks(){
  if (KEYS && Date.now() - KEYS_AT < 3600e3) return KEYS;
  const r = await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com");
  KEYS = (await r.json()).keys; KEYS_AT = Date.now(); return KEYS;
}
async function verify(tok){
  const [h, p, s] = tok.split(".");
  if (!s) throw 0;
  const head = JSON.parse(new TextDecoder().decode(b64u(h)));
  const body = JSON.parse(new TextDecoder().decode(b64u(p)));
  if (head.alg !== "RS256") throw 0;
  const jwk = (await jwks()).find(k => k.kid === head.kid);
  if (!jwk) throw 0;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64u(s), enc.encode(h + "." + p))) throw 0;
  const now = Date.now() / 1000;
  if (body.iss !== "https://securetoken.google.com/" + PROJECT || body.aud !== PROJECT) throw 0;
  if (!(body.exp > now) || body.iat > now + 300) throw 0;
  if (!body.email || !body.email_verified || (body.firebase || {}).sign_in_provider !== "google.com") throw 0;
  return String(body.email).toLowerCase();
}

const USE = new Map();
function rate(em){
  const d = new Date().toISOString().slice(0, 10), u = USE.get(em);
  if (!u || u.d !== d){ USE.set(em, { d, n: 1 }); return true; }
  return ++u.n <= DAILY_LIMIT;
}

export default {
  async fetch(req, env){
    const cors = { "Access-Control-Allow-Origin": ORIGIN, "Access-Control-Allow-Headers": "authorization, content-type", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Max-Age": "86400", "Vary": "Origin" };
    const J = (o, st = 200) => new Response(JSON.stringify(o), { status: st, headers: { ...cors, "content-type": "application/json; charset=utf-8" } });
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });
    if (req.method !== "POST") return J({ error: "hello", ok: true });
    if (req.headers.get("origin") !== ORIGIN) return J({ error: "origin" }, 403);
    let em;
    try { em = await verify((req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "")); } catch (e) { return J({ error: "auth" }, 401); }
    if (!FAMILY.includes(await sha(em))) return J({ error: "family" }, 403);
    if (!rate(em)) return J({ error: "rate_limited" }, 429);
    if (!env.ANTHROPIC_API_KEY) return J({ error: "no_key" }, 500);
    let b; try { b = await req.json(); } catch (e) { return J({ error: "body" }, 400); }
    const prompt = String(b.prompt || "");
    if (!prompt || prompt.length > 24000) return J({ error: "prompt" }, 400);
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: MODEL, max_tokens: b.tier === "quick" ? 1000 : 6000, system: SYSTEM, messages: [{ role: "user", content: prompt }] }),
    });
    if (!r.ok) return J({ error: "upstream", status: r.status, detail: (await r.text()).slice(0, 300) }, 502);
    const d = await r.json();
    return J({ text: (d.content || []).filter(c => c.type === "text").map(c => c.text).join("") });
  },
};
