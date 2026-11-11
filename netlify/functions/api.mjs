import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const SEC = () => process.env.TOKEN_SECRET || process.env.ADMIN_PASSWORD || "";
const mac = (b) => crypto.createHmac("sha256", SEC()).update(b).digest("base64url");
const sign = (p) => { const b = Buffer.from(JSON.stringify(p)).toString("base64url"); return b + "." + mac(b); };
const verify = (t) => {
  try {
    const [b, s] = t.split("."); const e = mac(b);
    if (!SEC() || s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return null;
    const p = JSON.parse(Buffer.from(b, "base64url").toString()); return p.exp > Date.now() ? p : null;
  } catch { return null; }
};
const J = (o, c = 200) => new Response(JSON.stringify(o), { status: c, headers: { "Content-Type": "application/json" } });

export default async (req) => {
  if (req.method !== "POST") return J({ error: "POST kerak" }, 405);
  const b = await req.json().catch(() => ({}));
  const st = getStore({ name: "savoljavob", consistency: "strong" });
  const S = (await st.get("state", { type: "json" })) || { students: [], groups: [], topics: [] };
  const getQ = async (sid) => (await st.get("q:" + sid, { type: "json" })) || {};

  if (b.action === "login") {
    const login = String(b.login || ""), pw = String(b.password || "");
    if (login === "admin") {
      if (process.env.ADMIN_PASSWORD && pw === process.env.ADMIN_PASSWORD)
        return J({ role: "admin", token: sign({ role: "admin", exp: Date.now() + 12 * 36e5 }) });
    } else {
      const s = pw && S.students.find((x) => x.login === login && x.pw === pw);
      if (s) return J({ role: "student", token: sign({ role: "student", id: s.id, exp: Date.now() + 7 * 864e5 }) });
    }
    return J({ error: "Login yoki parol xato" }, 401);
  }

  const u = verify((req.headers.get("authorization") || "").slice(7));
  if (!u) return J({ error: "Kirish talab qilinadi" }, 401);

  if (u.role === "admin") {
    if (b.action === "get") {
      const q = {};
      await Promise.all(S.students.map(async (s) => {
        const m = await getQ(s.id);
        for (const [tid, arr] of Object.entries(m)) (q[tid] ||= {})[s.id] = arr;
      }));
      return J({ state: S, q });
    }
    if (b.action === "save" && b.state && Array.isArray(b.state.students)) {
      await st.setJSON("state", b.state);
      return J({ ok: 1 });
    }
    return J({ error: "Nomaʼlum amal" }, 400);
  }

  const me = S.students.find((x) => x.id === u.id);
  if (!me) return J({ error: "Talaba topilmadi" }, 401);
  const mine = S.topics.filter((t) => t.gid === me.gid && t.asg.length && t.order.includes(me.id));

  if (b.action === "me") {
    const g = S.groups.find((x) => x.id === me.gid) || {};
    const nm = (id) => (S.students.find((x) => x.id === id) || {}).name || (S.topics.find((t) => t.names && t.names[id]) || { names: {} }).names[id] || "?";
    const own = await getQ(me.id);
    const cache = {};
    const ask = async (id) => (cache[id] ||= await getQ(id));
    const topics = [];
    for (const t of mine) {
      const inbox = [];
      for (const a of t.asg.filter((x) => x.to === me.id)) {
        const m = await ask(a.from);
        inbox.push({ from: nm(a.from), q: a.q, text: (m[t.id] || [])[a.q - 1] || "", r: a.r });
      }
      inbox.sort((x, y) => x.from.localeCompare(y.from) || x.q - y.q);
      topics.push({ id: t.id, name: t.name, k: t.k, mine: own[t.id] || [], inbox });
    }
    return J({ name: me.name, group: g.name, course: g.course, dir: g.dir, topics });
  }

  if (b.action === "submit") {
    const t = mine.find((x) => x.id === b.topicId);
    if (!t || !Array.isArray(b.questions)) return J({ error: "Mavzu topilmadi" }, 400);
    const own = await getQ(me.id);
    own[t.id] = b.questions.slice(0, t.k).map((x) => String(x || "").slice(0, 1000));
    await st.setJSON("q:" + me.id, own);
    return J({ ok: 1 });
  }
  return J({ error: "Nomaʼlum amal" }, 400);
};

export const config = { path: "/api" };
