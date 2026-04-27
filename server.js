const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;
const SHEETS_API = process.env.SHEETS_API_URL || 'https://script.google.com/macros/s/AKfycbzl3Cwrx5lsqIdmtaMOZhoIYimPhl3wEO1N8Q23SIQuhkjzsceLkoJ696djH7Z1sAZ7TA/exec';
const MEMBERS = {
  'G01': { name:'이슬', gender:'F', goal:'체중감량', goalWeight:70, protein:80, kcal:1800, startWeight:79.3, registered:'2025.09', trainer:'고승환', passwordHash:'' },
  'G02': { name:'김민준', gender:'M', goal:'근비대', goalWeight:85, protein:130, kcal:2800, startWeight:78.0, registered:'2025.10', trainer:'고승환', passwordHash:'' },
  'G03': { name:'박지현', gender:'F', goal:'체형교정', goalWeight:55, protein:70, kcal:1600, startWeight:60.2, registered:'2025.11', trainer:'고승환', passwordHash:'' },
  'ADMIN': { name:'고승환', gender:'M', goal:'트레이너', role:'admin', trainer:'NOW PT STUDIO', passwordHash:bcrypt.hashSync('nowpt2025!', 10) }
};
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: process.env.SESSION_SECRET || 'now-pt-secret-2025', resave: false, saveUninitialized: false, cookie: { secure: false, maxAge: 7*24*60*60*1000 } }));
function requireAuth(req, res, next) { if (req.session && req.session.memberCode) return next(); res.status(401).json({ error: '로그인이 필요합니다' }); }
app.post('/api/login', async (req, res) => {
  const { code, password } = req.body;
  const upperCode = (code||'').toUpperCase().trim();
  const member = MEMBERS[upperCode];
  if (!member) return res.status(401).json({ error: '등록되지 않은 코드입니다' });
  if (member.passwordHash === '') {
    req.session.memberCode = upperCode; req.session.memberName = member.name; req.session.role = member.role||'member';
    return res.json({ success:true, firstLogin:true, member:{ code:upperCode, name:member.name, goal:member.goal, role:member.role||'member' } });
  }
  const valid = await bcrypt.compare(password||'', member.passwordHash);
  if (!valid) return res.status(401).json({ error: '비밀번호가 올바르지 않습니다' });
  req.session.memberCode = upperCode; req.session.memberName = member.name; req.session.role = member.role||'member';
  res.json({ success:true, firstLogin:false, member:{ code:upperCode, name:member.name, goal:member.goal, role:member.role||'member' } });
});
app.post('/api/set-password', requireAuth, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: '4자 이상이어야 합니다' });
  MEMBERS[req.session.memberCode].passwordHash = await bcrypt.hash(newPassword, 10);
  res.json({ success:true });
});
app.get('/api/me', requireAuth, (req, res) => {
  const code = req.session.memberCode; const m = MEMBERS[code];
  res.json({ code, name:m.name, goal:m.goal, goalWeight:m.goalWeight, protein:m.protein, kcal:m.kcal, startWeight:m.startWeight, registered:m.registered, trainer:m.trainer, role:req.session.role, hasPassword:m.passwordHash!=='' });
});
app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success:true }); });
app.get('/api/data', requireAuth, async (req, res) => {
  try { const r = await fetch(`${SHEETS_API}?action=getAllData`); res.json(await r.json()); }
  catch(e) { res.status(500).json({ error: '시트 연결 실패: '+e.message }); }
});
app.post('/api/data', requireAuth, async (req, res) => {
  try {
    const { sheet, row } = req.body;
    row['회원코드'] = req.session.memberCode; row['회원명'] = req.session.memberName;
    const r = await fetch(SHEETS_API, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ action:'addRow', sheet, row }) });
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: '저장 실패: '+e.message }); }
});
app.get('/health', (req, res) => res.json({ status:'ok' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`✅ NOW PT 서버 실행: http://localhost:${PORT}`));
