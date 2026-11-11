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
  // Atomic per-question score claim: the first accepted write cannot be overwritten.
  const gradeKey = (topicId, a) => `grade:${topicId}:${a.from}:${a.to}:${a.q}`;
  const grade = async (topicId, a) => await st.get(gradeKey(topicId, a), { type: "json" });
  const gradesFor = async (t) => {
    await Promise.all((t.asg||[]).map(async a => {
      const g = await grade(t.id, a);
      if (g) { a.r = g.value; a.gradedBy = g.by; a.gradedAt = g.at; }
    }));
  };
  const current = t => (t.turnStartedAt && !t.turnFinishedAt && Number.isInteger(t.turnCursor)) ? t.turnQueue?.[t.turnCursor] : null;
  const stage = t => !current(t) ? 'Kutilmoqda' : Date.now() - t.turnProgressAt < t.turnPrepMinutes*60000 ? 'Tayyorlanish' : 'Javob berish';


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
    if (b.action === "turn-create") {
      const t = S.topics.find(t => t.id === b.topicId);
      if (!t || !t.asg.length || !t.order.length) return J({ error: "Avval savollarni taqsimlang" }, 400);
      if (t.turnStartedAt) return J({ error: "Navbat allaqachon boshlangan" }, 400);
      const minutes = Number(b.minutes), answerMinutes = Number(b.answerMinutes);
      if (!Number.isInteger(minutes) || minutes < 1 || minutes > 30 || !Number.isInteger(answerMinutes) || answerMinutes < 1 || answerMinutes > 30) return J({ error: "Vaqt 1–30 daqiqa bo‘lsin" }, 400);
      for (const id of t.order) {
        const own = await getQ(id);
        const q = own[t.id] || [];
        if (q.filter(x => typeof x === "string" && x.trim()).length < t.k)
          return J({ error: "Barcha talabalar savollarini to‘liq topshirmagan" }, 400);
      }
      const order = [...t.order];
      for (let i=order.length-1; i>0; i--) {
        const j = crypto.randomInt(i+1);
        [order[i],order[j]] = [order[j],order[i]];
      }
      t.turnQueue = order;
      t.turnPrepMinutes = minutes;
      t.turnAnswerMinutes = answerMinutes;
      t.turnStartedAt = null;
      t.turnProgressAt = null;
      t.turnCursor = 0;
      t.turnFinishedAt = null;
      await st.setJSON("state", S);
      return J({ ok: 1 });
    }
    if (b.action === "turn-start") {
      const t = S.topics.find(t => t.id === b.topicId);
      if (!t || !Array.isArray(t.turnQueue) || t.turnQueue.length !== t.order.length)
        return J({ error: "Avval navbat yarating" }, 400);
      if (t.turnStartedAt) return J({ error: "Navbat allaqachon boshlangan" }, 400);
      for (const id of t.order) {
        const own = await getQ(id);
        if ((own[t.id]||[]).filter(x=>typeof x === 'string' && x.trim()).length < t.k)
          return J({ error: "Hali barcha savollar topshirilmagan" }, 400);
      }
      t.turnStartedAt = Date.now();
      t.turnProgressAt = t.turnStartedAt;
      t.turnCursor = 0;
      t.turnFinishedAt = null;
      await st.setJSON("state", S);
      return J({ ok: 1 });
    }
    if (b.action === "turn-next") {
      const t = S.topics.find(t => t.id === b.topicId);
      if (!t || !current(t)) return J({error:"Faol navbat topilmadi"},400);
      const minMs = (t.turnPrepMinutes+t.turnAnswerMinutes)*60000;
      if (Date.now()-t.turnProgressAt < minMs) return J({error:"Har bir talaba uchun belgilangan teng vaqt hali tugamadi"},409);
      t.turnCursor++;
      t.turnProgressAt = Date.now();
      if (t.turnCursor >= t.turnQueue.length) t.turnFinishedAt = t.turnProgressAt;
      await st.setJSON("state", S);
      return J({ok:1});
    }
    if (b.action === "grade") {
      const t=S.topics.find(x=>x.id===b.topicId);
      const a=t?.asg?.find(x=>x.from===b.from&&x.to===b.to&&x.q===b.q);
      if (!a || ![1,2].includes(b.value)) return J({error:"Savol yoki baho noto‘g‘ri"},400);
      if (!t.turnStartedAt) return J({error:"Javob berish boshlanmagan"},400);
      if (current(t)!==a.to) return J({error:"Bu savol uchun hozir baholab bo‘lmaydi"},403);
      if (stage(t)!=='Javob berish') return J({error:"Tayyorlanish bosqichi davom etmoqda"},403);
      const key=gradeKey(t.id,a);
      const claim=await st.setJSON(key,{value:b.value,by:"admin",at:Date.now()},{onlyIfNew:true});
      const got=await grade(t.id,a);
      return J({ok:!!claim.modified,grade:got,already:!claim.modified});
    }
    if (b.action === "get") {
      await Promise.all(S.topics.map(gradesFor));
      const q = {};
      await Promise.all(S.students.map(async (s) => {
        const m = await getQ(s.id);
        for (const [tid, arr] of Object.entries(m)) (q[tid] ||= {})[s.id] = arr;
      }));
      return J({ state: S, q });
    }
    if (b.action === "save" && b.state && Array.isArray(b.state.students)) {
      // Keep server-owned turn state; ordinary admin edits must not roll back an active queue.
      for (const topic of b.state.topics || []) {
        const old = S.topics.find(x=>x.id===topic.id);
        if (old?.turnQueue?.length) {
          if (JSON.stringify(old.asg.map(a=>[a.from,a.to,a.q])) !== JSON.stringify((topic.asg||[]).map(a=>[a.from,a.to,a.q])))
            return J({error:"Boshlangan navbatning taqsimotini o‘zgartirib bo‘lmaydi"},400);
        }
        if (old?.turnQueue) {for(const prop of ['turnQueue','turnPrepMinutes','turnAnswerMinutes','turnStartedAt','turnProgressAt','turnCursor','turnFinishedAt'])topic[prop]=old[prop]??null;}
        // Scores belong exclusively to the score API; a stale browser save cannot revert them.
        if (old?.asg) for(const a of topic.asg||[]) {
          const prev=old.asg.find(x=>x.from===a.from&&x.to===a.to&&x.q===a.q);
          if(prev){a.r=prev.r||0;a.gradedAt=prev.gradedAt||null;a.gradedBy=prev.gradedBy||null;}
        }
      }
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
      await gradesFor(t);
      const currentId=current(t), myTurn=currentId===me.id;
      const inbox = [];
      if(myTurn){
        for (const a of t.asg.filter(x=>x.to===me.id)) {
          const m = await ask(a.from);
          inbox.push({ from: nm(a.from), q:a.q, text:(m[t.id]||[])[a.q-1]||"",r:a.r||0,gradedBy:a.gradedBy||null });
        }
      }
      inbox.sort((x,y)=>x.from.localeCompare(y.from)||x.q-y.q);
      const used=myTurn?Date.now()-t.turnProgressAt:0;
      const isPrep=myTurn && used<t.turnPrepMinutes*60000;
      const remainingSeconds=myTurn?Math.max(0,Math.ceil(((isPrep?t.turnPrepMinutes*60000:(t.turnPrepMinutes+t.turnAnswerMinutes)*60000)-used)/1000)):0;
      const turnLabel=t.turnFinishedAt?'Barcha navbatlar yakunlandi':t.turnStartedAt ? `Navbat ${t.turnCursor+1}/${t.turnQueue.length}` : 'Javob berish hali boshlanmagan';
      const outgoing=[];
      if(t.turnStartedAt && stage(t)==='Javob berish') {
        for (const a of t.asg.filter(x=>x.from===me.id && x.to===currentId)) {
          const ownQ=own[t.id]||[];
          outgoing.push({from:a.from,to:a.to,recipient:nm(a.to),q:a.q,text:ownQ[a.q-1]||'',r:a.r||0, gradedBy:a.gradedBy||null});
        }
      }
      topics.push({ id: t.id, name: t.name, k: t.k, mine: own[t.id] || [], inbox,
        turnStarted:!!t.turnStartedAt, questionsLocked:!!t.turnQueue?.length, myTurn, remainingSeconds, turnLabel, stage:isPrep?"Tayyorlanish":"Javob berish", outgoing,
        turnFinished:!!t.turnFinishedAt });
    }
    return J({ name: me.name, group: g.name, course: g.course, dir: g.dir, topics });
  }

  if (b.action === "grade") {
    const t=mine.find(x=>x.id===b.topicId);
    const a=t?.asg?.find(x=>x.from===me.id&&x.to===b.to&&x.q===b.q);
    if(!a||![1,2].includes(b.value))return J({error:"Savol yoki baho noto‘g‘ri"},400);
    if(current(t)!==a.to||stage(t)!=='Javob berish')return J({error:"Bu savol hozir baholanmaydi"},403);
    const result=await st.setJSON(gradeKey(t.id,a),{value:b.value,by:me.name,at:Date.now()},{onlyIfNew:true});
    const got=await grade(t.id,a);
    return J({ok:!!result.modified, grade:got, already:!result.modified});
  }
  if (b.action === "submit") {
    const t = mine.find((x) => x.id === b.topicId);
    if (!t || !Array.isArray(b.questions)) return J({ error: "Mavzu topilmadi" }, 400);
    if (t.turnQueue?.length) return J({error:"Navbat tuzilgan: savollarni tahrirlash yopilgan"},400);
    const own = await getQ(me.id);
    own[t.id] = b.questions.slice(0, t.k).map((x) => String(x || "").slice(0, 1000));
    await st.setJSON("q:" + me.id, own);
    return J({ ok: 1 });
  }
  return J({ error: "Nomaʼlum amal" }, 400);
};

export const config = { path: "/api" };
