// 우리가족 AI 연결 서버 (Cloudflare Worker · 이름: hihoho-ai)
// - 가족 구글 계정(Firebase 로그인)만 사용 가능
// - 우리 주소(rmsgp11-ui.github.io)에서 온 요청만 받음
// - Claude API 키는 Cloudflare 비밀 변수 ANTHROPIC_API_KEY 에만 저장 (코드에 없음)
// - 학습 문제 만들기·피드백만 (문제집 지문 사진 읽기 포함)
// - /ingest : 아이폰 단축어(애플페이 거래)가 보낸 결제를 KV에 잠시 보관 (비밀 변수 INGEST_TOKEN 필요)
// - /pull   : 보호자 앱이 보관된 결제를 가져가 가계부에 적음 (KV 바인딩 이름: KV) 하고 JSON으로만 답함, 한 사람당 하루 횟수 제한

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
const ADMIN = [FAMILY[0], FAMILY[1]];
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
    const url = new URL(req.url);
    if (url.pathname === "/ingest"){
      const plain = (o, st = 200) => new Response(JSON.stringify(o), { status: st, headers: { "content-type": "application/json; charset=utf-8" } });
      if (!env.KV || !env.INGEST_TOKEN) return plain({ error: "not_ready" }, 500);
      const tok = req.headers.get("x-token") || url.searchParams.get("t") || "";
      if (tok !== env.INGEST_TOKEN) return plain({ error: "token" }, 403);
      const rawBody = await req.text().catch(() => "");
      let b = {}; try { b = JSON.parse(rawBody); } catch (e) { try { b = Object.fromEntries(new URLSearchParams(rawBody)); if (!Object.keys(b).some(k => /amount|금액|sms|text|문자/.test(k))) b = { sms: rawBody }; } catch (x) { b = { sms: rawBody }; } }
      if (!b || typeof b !== "object" || Array.isArray(b)) b = { sms: typeof b === "string" ? b : JSON.stringify(b) };
      const flat = v => v == null ? "" : typeof v === "string" ? v : Array.isArray(v) ? v.map(flat).join(" ") : typeof v === "object" ? Object.values(v).map(flat).join(" ") : String(v);
      let smsTxt = flat(b.sms ?? b.text ?? b.문자 ?? "");
      if (!smsTxt && !(b.amount ?? b.금액)){ const any = Object.values(b).map(flat).find(v => /원/.test(v)); if (any) smsTxt = any; }
      const logIt = async (res) => { try { await env.KV.put("log:last", JSON.stringify({ at: Date.now(), keys: Object.keys(b).slice(0, 8), len: rawBody.length, smsLen: smsTxt.length, res }), { expirationTtl: 60 * 60 * 24 * 7 }); } catch (e) {} };
      if (smsTxt){
        // 은행 입출금 문자 한 통을 받아 입금/출금·금액·상대·잔액을 뽑아 둠
        const txt = smsTxt.replace(/\s+/g, " ").slice(0, 400);
        const num = s => Math.round(Math.abs(parseFloat(String(s || "").replace(/[^0-9.]/g, "")) || 0));
        let o = null;
        try {
          const r = await fetch("https://api.anthropic.com/v1/messages", { method: "POST", headers: { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
            body: JSON.stringify({ model: MODEL, max_tokens: 150, system: "너는 은행 문자 해석기야. JSON 한 줄로만 답해.", messages: [{ role: "user", content: `아래는 은행/카드 알림 문자야.\n${txt}\n\n{"kind":"out|in|none","amt":숫자,"who":"가게나 보낸·받은 사람","bal":잔액숫자또는null,"cat":"식재료|그 외|입금"} 형식으로 답해. 출금·결제·이체 보냄=out, 입금·받음·환불=in, 입출금이 아니면(광고·인증번호·승인취소 안내 등) none. cat은 in이면 "입금", out이면 먹거리 사는 곳(마트·식품점·정육점·과일·빵집·반찬·편의점)이면 "식재료", 나머지는 "그 외".` }] }) });
          if (r.ok){ const d = await r.json(); const t = (d.content || []).map(c => c.text || "").join(""); const m = t.match(/\{[\s\S]*\}/); if (m) o = JSON.parse(m[0]); }
        } catch (e) {}
        if (!o){ // AI가 안 될 때 간단 규칙
          const am = txt.match(/([0-9][0-9,]*)\s*원/), bl = txt.match(/잔액\s*:?\s*([0-9][0-9,]*)/);
          o = { kind: /입금|받음|환불/.test(txt) ? "in" : /출금|결제|승인|이체|보냄/.test(txt) ? "out" : "none", amt: am ? am[1] : 0, who: "", bal: bl ? bl[1] : null };
        }
        const kind = o.kind === "in" ? "in" : o.kind === "out" ? "out" : "none", amt = num(o.amt), bal = o.bal == null || o.bal === "" ? null : num(o.bal);
        if (kind === "none" || !amt){ await logIt("skip"); return plain({ ok: true, skip: true }); }
        const at = Date.now(), id = "tx" + at.toString(36) + Math.random().toString(36).slice(2, 6);
        const cat = kind === "in" ? "입금" : (o.cat === "식재료" ? "식재료" : "그 외");
        await env.KV.put("tx:" + id, JSON.stringify({ id, at, amt, merchant: String(o.who || "").slice(0, 40), cat, kind, bal, src: "sms" }), { expirationTtl: 60 * 60 * 24 * 60 });
        await logIt(kind + " " + amt); return plain({ ok: true, kind, amt, bal, cat });
      }
      const raw = String(b.amount ?? b.금액 ?? "");
      const amt = Math.round(Math.abs(parseFloat(raw.replace(/[^0-9.\-]/g, "")) || 0));
      const merchant = String(b.merchant ?? b.가맹점 ?? "").slice(0, 60).trim();
      if (!amt){ await logIt("empty"); return plain({ error: "empty", keys: Object.keys(b).slice(0, 8), len: rawBody.length }, 400); }
      let cat = "그 외";
      try {
        const r = await fetch("https://api.anthropic.com/v1/messages", { method: "POST", headers: { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
          body: JSON.stringify({ model: MODEL, max_tokens: 50, messages: [{ role: "user", content: `가족 가계부. 결제한 곳: "${merchant}". 마트·식품점·정육점·과일가게·빵집·반찬가게·편의점처럼 먹거리를 사는 곳이면 "식재료", 그 밖(식당, 학원, 병원, 옷, 생활용품, 교통 등)이면 "그 외". 단어 하나만 답해.` }] }) });
        if (r.ok){ const d = await r.json(); const t = (d.content || []).map(c => c.text || "").join(""); if (t.includes("식재료")) cat = "식재료"; }
      } catch (e) {}
      const at = Date.now(), id = "tx" + at.toString(36) + Math.random().toString(36).slice(2, 6);
      await env.KV.put("tx:" + id, JSON.stringify({ id, at, amt, merchant, card: String(b.card ?? b.카드 ?? "").slice(0, 30), cat }), { expirationTtl: 60 * 60 * 24 * 60 });
      return plain({ ok: true, amt, merchant, cat });
    }
    if (req.method !== "POST") return J({ ok: true, v: "5-sms" });
    if (req.headers.get("origin") !== ORIGIN) return J({ error: "origin" }, 403);
    let em;
    try { em = await verify((req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "")); } catch (e) { return J({ error: "auth" }, 401); }
    if (!FAMILY.includes(await sha(em))) return J({ error: "family" }, 403);
    if (!rate(em)) return J({ error: "rate_limited" }, 429);
    if (url.pathname === "/pull"){
      if (!env.KV) return J({ error: "no_kv" }, 500);
      if (!ADMIN.includes(await sha(em))) return J({ error: "not_admin" }, 403);
      const list = await env.KV.list({ prefix: "tx:" }); const items = [];
      for (const k of list.keys){ const v = await env.KV.get(k.name); if (v) { try { items.push(JSON.parse(v)); } catch (e) {} } }
      if ((await req.clone().json().catch(() => ({}))).ack) for (const k of list.keys) await env.KV.delete(k.name);
      let log = null; try { log = JSON.parse(await env.KV.get("log:last") || "null"); } catch (e) {}
      return J({ items, log });
    }
    if (url.pathname === "/ack"){
      if (!env.KV) return J({ error: "no_kv" }, 500);
      if (!ADMIN.includes(await sha(em))) return J({ error: "not_admin" }, 403);
      let b = {}; try { b = await req.json(); } catch (e) {}
      for (const id of (b.ids || []).slice(0, 200)) await env.KV.delete("tx:" + String(id));
      return J({ ok: true });
    }
    if (!env.ANTHROPIC_API_KEY) return J({ error: "no_key" }, 500);
    let b; try { b = await req.json(); } catch (e) { return J({ error: "body" }, 400); }
    const prompt = String(b.prompt || "");
    if (!prompt || prompt.length > 24000) return J({ error: "prompt" }, 400);
    let content = prompt;
    if (b.image){
      const im = b.image, mt = String(im.media_type || "");
      if (!/^image\/(jpeg|png|webp)$/.test(mt) || typeof im.data !== "string" || im.data.length > 3000000) return J({ error: "image" }, 400);
      content = [{ type: "image", source: { type: "base64", media_type: mt, data: im.data } }, { type: "text", text: prompt }];
    }
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: MODEL, max_tokens: b.tier === "quick" ? 1000 : 6000, system: SYSTEM, messages: [{ role: "user", content }] }),
    });
    if (!r.ok) return J({ error: "upstream", status: r.status, detail: (await r.text()).slice(0, 300) }, 502);
    const d = await r.json();
    return J({ text: (d.content || []).filter(c => c.type === "text").map(c => c.text).join("") });
  },
};
