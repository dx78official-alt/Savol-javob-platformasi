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
  const progressKey = (topicId, sid) => `progress:${topicId}:${sid}`;
  const getProgress = async (topicId, sid) => await st.get(progressKey(topicId, sid), { type: "json" });
  const getQ = async (sid) => (await st.get("q:" + sid, { type: "json" })) || {};
  // Atomic per-question score claim: the first accepted write cannot be overwritten.
  const gradeKey = (topicId, a) => `grade:${topicId}:${a.from}:${a.to}:${a.q}`;
  const grade = async (topicId, a) => await st.get(gradeKey(topicId, a), { type: "json" });
  const gradesFor = async (t) => {
    await Promise.all((t.asg||[]).map(async a => {
      const g = await grade(t.id, a);
      if (g) { a.r = g.scale === 5 ? g.value : (g.value === 1 ? 5 : 0); a.gradedBy = g.by; a.gradedAt = g.at; }
    }));
  };
  // One preparation window per visible question. There is NO answer countdown.
  // The respondent may end preparation early. Only the reviewer/admin may grade.
  const current = t => (t.turnStartedAt && !t.turnFinishedAt && Number.isInteger(t.turnCursor)) ? t.turnQueue?.[t.turnCursor] : null;
  const entries = t => (t.asg || []).filter(a => a.to === current(t)).sort((a,b)=>a.q-b.q);
  const prepMs = t => (t.turnPrepMinutes || 2) * 60000;
  const stage = t => {
    if (!current(t) || !entries(t)[t.questionCursor]) return 'Kutilmoqda';
    const earlyReady = t.questionReadyAt && t.questionReadyAt >= t.questionStartedAt;
    return earlyReady || Date.now() >= (t.questionStartedAt || Date.now()) + prepMs(t) ? 'Javob berish' : 'Tayyorlanish';
  };
  const nextQuestion = async t => {
    if (!current(t)) return false;
    if (!Number.isInteger(t.questionCursor)) t.questionCursor = 0;
    if (!t.questionStartedAt) t.questionStartedAt = t.turnProgressAt || t.turnStartedAt;
    let moved = false;
    const list = entries(t);
    while (t.questionCursor < list.length) {
      const a = list[t.questionCursor], got = await grade(t.id, a);
      // Do not move until a first accepted grade exists. A delayed grade is valid.
      if (!got) break;
      t.questionCursor++;
      // Next question is visible as soon as the grade is accepted.
      t.questionStartedAt = Date.now();
      t.questionReadyAt = null;
      moved = true;
    }
    return moved;
  };
  const reconcile = async () => {
    let changed = false;
    for (const t of S.topics) if (await nextQuestion(t)) changed = true;
    if (changed) await st.setJSON('state', S);
  };
  await reconcile();
  const scoreValid = x => Number.isInteger(x) && x >= 0 && x <= 5;
  const rankings = t => {
    const results = (t.order || []).map(id => {
      const a = (t.asg || []).filter(a => a.to === id);
      // Every question must be graded to advance; missing grades are reported separately.
      const sum = a.reduce((v, q) => v + (q.gradedAt ? Number(q.r) || 0 : 0), 0);
      return {id, average: a.length ? Math.round(sum/a.length*100)/100 : 0,
        sum, count:a.length, rated:a.filter(q=>q.gradedAt).length,
        ungraded:a.length-a.filter(q=>q.gradedAt).length};
    });
    results.sort((a,b)=>b.average-a.average||b.sum-a.sum||(t.order||[]).indexOf(a.id)-(t.order||[]).indexOf(b.id));
    let last=null, place=0;
    results.forEach((x,i)=>{if(x.average!==last){place=i+1;last=x.average;}x.place=place;});
    return results;
  };
  const finishedTopic = t => Boolean(t.turnFinishedAt && (t.turnQueue || []).length);

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
      const minutes = Number(b.minutes);
      if (!Number.isInteger(minutes) || minutes < 1 || minutes > 30) return J({ error: "Tayyorlanish vaqti 1–30 daqiqa bo‘lsin" }, 400);
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
      delete t.turnAnswerMinutes;
      t.showQuestionAuthor = b.showQuestionAuthor === true;
      t.questionCursor = 0;
      t.questionStartedAt = null;
      t.questionReadyAt = null;
      t.turnStartedAt = null;
      t.turnProgressAt = null;
      t.turnCursor = 0;
      t.turnFinishedAt = null;
      await st.setJSON("state", S);
      return J({ ok: 1 });
    }
    if (b.action === "turn-settings") {
      const t = S.topics.find(x => x.id === b.topicId);
      if (!t) return J({error:"Mavzu topilmadi"},404);
      if (t.turnFinishedAt) return J({error:"Yakunlangan mavzu sozlamalari o‘zgartirilmaydi"},409);
      if (typeof b.showQuestionAuthor === 'boolean') t.showQuestionAuthor = b.showQuestionAuthor;
      if (b.minutes !== undefined) {
        if (t.turnStartedAt) return J({error:"Navbat boshlangan: vaqtni o‘zgartirish mumkin emas"},409);
        if (!Number.isInteger(b.minutes) || b.minutes<1 || b.minutes>30)
          return J({error:"Tayyorlanish vaqti 1–30 daqiqa bo‘lsin"},400);
        t.turnPrepMinutes=b.minutes;
      }
      await st.setJSON('state',S);
      return J({ok:1});
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
      t.questionCursor = 0;
      t.questionStartedAt = t.turnStartedAt;
      t.questionReadyAt = null;
      await st.setJSON("state", S);
      return J({ ok: 1 });
    }
    if (b.action === "turn-next") {
      const t = S.topics.find(t => t.id === b.topicId);
      if (!t || !current(t)) return J({error:"Faol navbat topilmadi"},400);
      await nextQuestion(t);
      if(t.questionCursor < entries(t).length) return J({error:"Talabaning barcha savollari yakunlanmagan. Keyingi savolni kuting."},409);
      t.turnCursor++;
      t.turnProgressAt = Date.now();
      t.questionCursor = 0;
      t.questionStartedAt = t.turnProgressAt;
      t.questionReadyAt = null;
      if (t.turnCursor >= t.turnQueue.length) t.turnFinishedAt = t.turnProgressAt;
      await st.setJSON("state", S);
      return J({ok:1});
    }
    if (b.action === "grade") {
      const t=S.topics.find(x=>x.id===b.topicId);
      const a=t?.asg?.find(x=>x.from===b.from&&x.to===b.to&&x.q===b.q);
      if (!a || !scoreValid(b.value)) return J({error:"Savol yoki baho noto‘g‘ri"},400);
      if (!t.turnStartedAt) return J({error:"Javob berish boshlanmagan"},400);
      if (current(t)!==a.to) return J({error:"Bu savol uchun hozir baholab bo‘lmaydi"},403);
      if (stage(t)!=='Javob berish' || entries(t)[t.questionCursor]!==a) return J({error:"Faqat javob berish bosqichidagi savol baholanadi"},403);
      const key=gradeKey(t.id,a);
      const claim=await st.setJSON(key,{value:b.value,by:"admin",at:Date.now(),scale:5},{onlyIfNew:true});
      const got=await grade(t.id,a);
      if(claim.modified) await reconcile();
      return J({ok:!!claim.modified,grade:got,already:!claim.modified});
    }
    if (b.action === "get") {
      await Promise.all(S.topics.map(gradesFor));
      const q = {};
      await Promise.all(S.students.map(async (s) => {
        const m = await getQ(s.id);
        for (const [tid, arr] of Object.entries(m)) (q[tid] ||= {})[s.id] = arr;
      }));
      const progress = {};
      await Promise.all(S.topics.flatMap(t => (t.order||[]).map(async sid => {
        const p=await getProgress(t.id,sid);
        if(p) (progress[t.id] ||= {})[sid] = p;
      })));
      return J({ state: S, q, progress, serverNow: Date.now() });
    }
    if (b.action === "save" && b.state && Array.isArray(b.state.students)) {
      // Keep server-owned turn state; ordinary admin edits must not roll back an active queue.
      for (const topic of b.state.topics || []) {
        const old = S.topics.find(x=>x.id===topic.id);
        if (old?.turnQueue?.length) {
          if (JSON.stringify(old.asg.map(a=>[a.from,a.to,a.q])) !== JSON.stringify((topic.asg||[]).map(a=>[a.from,a.to,a.q])))
            return J({error:"Boshlangan navbatning taqsimotini o‘zgartirib bo‘lmaydi"},400);
        }
        if (old?.turnQueue) {for(const prop of ['turnQueue','turnPrepMinutes','turnStartedAt','turnProgressAt','turnCursor','turnFinishedAt','questionCursor','questionStartedAt','questionReadyAt','showQuestionAuthor'])topic[prop]=old[prop]??null;}
        // Scores belong exclusively to the score API; a stale browser save cannot revert them.
        if (old?.asg) for(const a of topic.asg||[]) {
          const prev=old.asg.find(x=>x.from===a.from&&x.to===a.to&&x.q===a.q);
          if(prev){a.r=prev.r??null;a.gradedAt=prev.gradedAt||null;a.gradedBy=prev.gradedBy||null;}
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
      if(myTurn) {
        const a=entries(t)[t.questionCursor];
        if(a){const m=await ask(a.from);inbox.push({from:t.showQuestionAuthor?nm(a.from):null,q:t.questionCursor+1,text:(m[t.id]||[])[a.q-1]||'',r:a.r??null,gradedAt:a.gradedAt||null,gradedBy:a.gradedBy||null});}
      }
      const used=myTurn?Date.now()-(t.questionStartedAt||Date.now()):0;
      const isPrep=myTurn && !!entries(t)[t.questionCursor] && stage(t)==='Tayyorlanish';
      const currentA=currentId?entries(t)[t.questionCursor]:null;
      const remainingSeconds=myTurn&&currentA&&isPrep ? Math.max(0,Math.ceil(((t.questionStartedAt+prepMs(t))-Date.now())/1000)) : 0;
      const turnLabel=t.turnFinishedAt?'Barcha navbatlar yakunlandi':t.turnStartedAt ? `Navbat ${t.turnCursor+1}/${t.turnQueue.length}` : 'Javob berish hali boshlanmagan';
      const outgoing=[];
      if(t.turnStartedAt && stage(t)==='Javob berish') {
        for (const a of t.asg.filter(x=>x.from===me.id && x.to===currentId && x===currentA)) {
          const ownQ=own[t.id]||[];
          outgoing.push({from:a.from,to:a.to,recipient:nm(a.to),q:a.q,text:ownQ[a.q-1]||'',r:a.r??null, gradedAt:a.gradedAt||null, gradedBy:a.gradedBy||null});
        }
      }
      const myRank = finishedTopic(t) ? rankings(t).find(x=>x.id===me.id) : null;
      topics.push({ id: t.id, name: t.name, k: t.k, mine: own[t.id] || [], inbox, showQuestionAuthor:!!t.showQuestionAuthor, ranking:myRank, rankingTotal:(t.order||[]).length,
        turnStarted:!!t.turnStartedAt, questionsLocked:!!t.turnQueue?.length, myTurn, remainingSeconds, turnLabel, stage:isPrep?"Tayyorlanish":"Javob berish", outgoing,
        turnFinished:!!t.turnFinishedAt, questionIndex:t.questionCursor||0, questionCount:currentId?entries(t).length:0, waitingForAdmin:myTurn&&!currentA });
    }
    return J({ name: me.name, group: g.name, course: g.course, dir: g.dir, topics });
  }

  if (b.action === "ready") {
    const t=mine.find(x=>x.id===b.topicId);
    if (!t || current(t)!==me.id || !entries(t)[t.questionCursor])
      return J({error:"Sizning faol savolingiz yo‘q"},403);
    if (stage(t)==='Tayyorlanish') {
      // Another request may have moved the question; require the exact cursor.
      if (Number(b.questionIndex)!==t.questionCursor) return J({error:"Savol allaqachon almashgan"},409);
      t.questionReadyAt=Date.now();
      await st.setJSON('state',S);
    }
    return J({ok:1});
  }
  if (b.action === "grade") {
    const t=mine.find(x=>x.id===b.topicId);
    const a=t?.asg?.find(x=>x.from===me.id&&x.to===b.to&&x.q===b.q);
    if(!a||!scoreValid(b.value))return J({error:"Savol yoki baho noto‘g‘ri"},400);
    if(current(t)!==a.to||stage(t)!=='Javob berish'||entries(t)[t.questionCursor]!==a)return J({error:"Bu savol hozir baholanmaydi"},403);
    const result=await st.setJSON(gradeKey(t.id,a),{value:b.value,by:me.name,at:Date.now(),scale:5},{onlyIfNew:true});
    const got=await grade(t.id,a);
    if(result.modified) await reconcile();
    return J({ok:!!result.modified, grade:got, already:!result.modified});
  }
  if (b.action === "progress") {
    const t=mine.find(x=>x.id===b.topicId);
    if(!t) return J({error:"Mavzu topilmadi"},400);
    const active=Number.isInteger(b.activeQuestion)&&b.activeQuestion>=1&&b.activeQuestion<=t.k&&!t.turnQueue?.length
      ? b.activeQuestion : null;
    await st.setJSON(progressKey(t.id,me.id), {activeQuestion:active, updatedAt:Date.now()});
    return J({ok:1});
  }
  if (b.action === "submit") {
    const t = mine.find((x) => x.id === b.topicId);
    if (!t || !Array.isArray(b.questions)) return J({ error: "Mavzu topilmadi" }, 400);
    if (t.turnQueue?.length) return J({error:"Navbat tuzilgan: savollarni tahrirlash yopilgan"},400);
    const own = await getQ(me.id);
    own[t.id] = b.questions.slice(0, t.k).map((x) => String(x || "").slice(0, 1000));
    await st.setJSON("q:" + me.id, own);
    const active=Number.isInteger(b.activeQuestion)&&b.activeQuestion>=1&&b.activeQuestion<=t.k ? b.activeQuestion : null;
    await st.setJSON(progressKey(t.id,me.id), {activeQuestion:active, updatedAt:Date.now()});
    return J({ ok: 1 });
  }
  return J({ error: "Nomaʼlum amal" }, 400);
};

export const config = { path: "/api" };
