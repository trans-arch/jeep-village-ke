const crypto=require('node:crypto');
module.exports=function(db){
 db.exec(`CREATE TABLE IF NOT EXISTS staff(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,password TEXT NOT NULL,role TEXT NOT NULL,worker TEXT,active INTEGER NOT NULL DEFAULT 1);
 CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS auth_limits(key TEXT PRIMARY KEY,count INTEGER NOT NULL,expires INTEGER NOT NULL);`);
 const online=!!process.env.RENDER,secure=online||process.env.NODE_ENV==='production';
 const fail=(message,status=400)=>{throw Object.assign(Error(message),{status})};
 const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
 const password=p=>{if(typeof p!=='string'||p.length<12||p.length>200)fail('Use a password of 12–200 characters.');const salt=crypto.randomBytes(16).toString('hex');return salt+':'+crypto.scryptSync(p,salt,64).toString('hex')};
 const verify=(p,stored)=>{const [salt,key]=stored.split(':');return crypto.timingSafeEqual(Buffer.from(key,'hex'),crypto.scryptSync(p,salt,64))};
 const safe=u=>({id:u.id,name:u.name,email:u.email,role:u.role,worker:u.worker,active:!!u.active});
 const email=s=>String(s||'').trim().toLowerCase();
 const json=(res,data,status=200)=>{res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(data))};
 async function body(req){let s='';for await(const c of req){s+=c;if(s.length>20000)fail('Request too large.',413)}return JSON.parse(s||'{}')}
 function rate(key,max,minutes){const now=Date.now();db.prepare('DELETE FROM auth_limits WHERE expires<?').run(now);db.prepare('INSERT INTO auth_limits(key,count,expires) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1').run(key,now+minutes*60000);if(db.prepare('SELECT count FROM auth_limits WHERE key=?').get(key).count>max)fail('Too many attempts. Please try again later.',429)}
 function origin(req){if(req.headers['sec-fetch-site']==='cross-site')fail('Cross-site request blocked.',403);if(req.headers.origin){const expected=process.env.PUBLIC_ORIGIN||((online?'https':'http')+'://'+req.headers.host);if(req.headers.origin!==expected)fail('Origin not allowed.',403)}}
 function current(req){const token=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('jv_session='))?.slice(11);if(!token)return null;return db.prepare('SELECT staff.* FROM sessions JOIN staff ON staff.id=sessions.user_id WHERE sessions.token=? AND sessions.expires>? AND staff.active=1').get(hash(token),Date.now())||null}
 function session(res,user){const token=crypto.randomBytes(32).toString('hex');db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now());db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(hash(token),user.id,Date.now()+8*60*60*1000);res.setHeader('Set-Cookie','jv_session='+token+'; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'+(secure?'; Secure':''))}
 function requireUser(req){const u=current(req);if(!u)fail('Please sign in.',401);return u}
 function requireDirector(u){if(u.role!=='director')fail('Director access required.',403)}
 async function handle(req,res,url){
  if(req.method!=='GET'&&req.method!=='HEAD')origin(req);
  if(url.pathname==='/health'){json(res,{ok:true});return true}
  if(url.pathname==='/api/auth/me'){const user=current(req);json(res,{user:user?safe(user):null,setupRequired:!db.prepare('SELECT 1 FROM staff LIMIT 1').get(),online});return true}
  if(['/api/auth/setup','/api/auth/login'].includes(url.pathname)){
   if(req.method!=='POST')fail('Method not allowed.',405);
   const input=await body(req),address=online?String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',').at(-1).trim():req.socket.remoteAddress;
   rate('ip:'+address,40,15);rate('email:'+email(input.email),10,15);
   if(url.pathname.endsWith('setup')){
    if(db.prepare('SELECT 1 FROM staff LIMIT 1').get())fail('Initial setup is already complete.',403);
    if(online||process.env.NODE_ENV==='production'){const expected=process.env.BOOTSTRAP_TOKEN;if(!expected||hash(String(input.token||''))!==hash(expected))fail('Enter the setup token from your hosting environment.',403)}
    const name=String(input.name||'').trim(),mail=email(input.email);if(!name||!/^\S+@\S+\.\S+$/.test(mail))fail('Enter your name and a valid email.');
    const result=db.prepare('INSERT INTO staff(name,email,password,role) VALUES(?,?,?,?)').run(name,mail,password(input.password),'director');
    const user=db.prepare('SELECT * FROM staff WHERE id=?').get(result.lastInsertRowid);session(res,user);json(res,{user:safe(user)});return true;
   }
   const user=db.prepare('SELECT * FROM staff WHERE email=? AND active=1').get(email(input.email));
   const p=typeof input.password==='string'&&input.password.length<=200?input.password:'';
   if(!user){crypto.scryptSync(p,'invalid-login-padding',64);fail('Email or password is incorrect.',401)}
   if(!verify(p,user.password))fail('Email or password is incorrect.',401);session(res,user);json(res,{user:safe(user)});return true;
  }
  if(url.pathname==='/api/auth/logout'){
   if(req.method!=='POST')fail('Method not allowed.',405);const token=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('jv_session='))?.slice(11);if(token)db.prepare('DELETE FROM sessions WHERE token=?').run(hash(token));res.setHeader('Set-Cookie','jv_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'+(secure?'; Secure':''));json(res,{ok:true});return true;
  }
  if(url.pathname==='/api/auth/password'){
   if(req.method!=='POST')fail('Method not allowed.',405);const user=requireUser(req),input=await body(req);rate('password:'+user.id,10,15);if(!verify(String(input.current||'').slice(0,200),user.password))fail('Current password is incorrect.',403);db.prepare('UPDATE staff SET password=? WHERE id=?').run(password(input.password),user.id);db.prepare('DELETE FROM sessions WHERE user_id=?').run(user.id);session(res,user);json(res,{ok:true});return true;
  }
  if(url.pathname==='/api/staff'){
   const user=requireUser(req);requireDirector(user);
   if(req.method==='GET'){json(res,db.prepare('SELECT * FROM staff ORDER BY name').all().map(safe));return true}
   if(req.method!=='POST')fail('Method not allowed.',405);const input=await body(req),role=input.role,mail=email(input.email),name=String(input.name||'').trim();
   if(!['director','secretary','technician'].includes(role)||!name||!/^\S+@\S+\.\S+$/.test(mail))fail('Enter name, email and a valid role.');
   const worker=role==='technician'?String(input.worker||''):'';
   if(role==='technician'&&!db.prepare("SELECT 1 FROM records WHERE id=? AND kind='workers'").get(worker))fail('Link the technician to an existing worker.');
   if(role==='technician'&&db.prepare("SELECT 1 FROM staff WHERE worker=? AND role='technician' AND active=1 AND id<>?").get(worker,input.id||0))fail('This worker already has an active account.');
   const active=input.active===false?0:1;
   const newPassword=input.password?password(input.password):null;if(!input.id&&!newPassword)fail('A password is required.');
   if(input.id){const target=db.prepare('SELECT * FROM staff WHERE id=?').get(input.id);if(!target)fail('Account not found.');if(target.id===user.id&&(!active||role!=='director'))fail('You cannot disable or demote your own director account.');
    db.prepare('UPDATE staff SET name=?,email=?,role=?,worker=?,active=? WHERE id=?').run(name,mail,role,worker,active,input.id);
    if(newPassword)db.prepare('UPDATE staff SET password=? WHERE id=?').run(newPassword,input.id);
    db.prepare('DELETE FROM sessions WHERE user_id=?').run(input.id);
   }else db.prepare('INSERT INTO staff(name,email,password,role,worker,active) VALUES(?,?,?,?,?,?)').run(name,mail,newPassword,role,worker,active);
   json(res,{ok:true});return true;
  }
  return false;
 }
 function visible(user,rows){if(user.role==='director')return rows;
  if(user.role==='technician')return rows.filter(r=>r.kind==='jobs'&&String(r.worker)===String(user.worker)).map(r=>Object.fromEntries(['id','kind','vehicle','registration','complaint','status','worker','date','finished','finishedAt','finishedBy'].map(k=>[k,r[k]])));
  return rows.filter(r=>['jobs','bookings','inventory','workers'].includes(r.kind)||(r.kind==='cashbook'&&r.type==='Customer receipt')).map(r=>{if(r.kind==='workers')return{id:r.id,kind:r.kind,name:r.name,role:r.role};const clean={...r};delete clean.workerCost;delete clean.partCost;delete clean.cost;return clean});
 }
 const allowedFields={jobs:['customer','phone','vehicle','registration','complaint','status','worker','labour','workerCost','part','quantity','date'],workers:['name','phone','joined','pay','basis','role','notes'],inventory:['name','sku','quantity','cost','price','reorder'],bills:['supplier','description','category','amount','date','due'],cashbook:['type','amount','job','bill','worker','date','notes'],bookings:['customer','phone','email','vehicle','registration','service','date','time','complaint','status','notes']};
 function write(user,id,kind,input){
  if(user.role==='technician')fail('Technicians may only update completion of their assigned jobs.',403);
  if(user.role==='secretary'&&!['jobs','bookings','cashbook'].includes(kind))fail('Director access required.',403);
  const old=id?db.prepare('SELECT * FROM records WHERE id=? AND kind=?').get(id,kind):null;if(id&&!old)fail('Record not found.',404);
  const previous=old?JSON.parse(old.data):{};
  if(user.role==='secretary'&&kind==='cashbook'&&(input.type!=='Customer receipt'||(old&&previous.type!=='Customer receipt')))fail('Only customer receipts are permitted.',403);
  const data={...previous};for(const key of allowedFields[kind]||[])if(Object.hasOwn(input,key)&&!(user.role==='secretary'&&key==='workerCost'))data[key]=input[key];
  for(const key of ['pay','labour','workerCost','quantity','cost','price','reorder','amount'])if(Object.hasOwn(data,key)){data[key]=Number(data[key]);if(!Number.isFinite(data[key])||data[key]<0)fail('Amounts and quantities must be nonnegative numbers.');}
  if(kind==='cashbook'&&!(data.amount>0))fail('Enter an amount greater than zero.');
  if(kind==='jobs'){
   if(data.worker&&!db.prepare("SELECT 1 FROM records WHERE id=? AND kind='workers'").get(data.worker))fail('Choose a valid worker.');
   const part=data.part?db.prepare("SELECT data FROM records WHERE id=? AND kind='inventory'").get(data.part):null;if(data.part&&!part)fail('Part not found.');const p=part?JSON.parse(part.data):null;
   if(Number(data.quantity||0)>0&&!p)fail('Select a part for this quantity.');
   const other=db.prepare("SELECT id,data FROM records WHERE kind='jobs'").all().filter(r=>r.id!==Number(id||0)).map(r=>JSON.parse(r.data)).filter(j=>String(j.part)===String(data.part)).reduce((s,j)=>s+Number(j.quantity||0),0);
   if(p&&Number(data.quantity||0)>Number(p.quantity)-other)fail('Not enough stock.');
   data.partCost=old&&String(previous.part)===String(data.part)?previous.partCost:p?.cost||0;data.partPrice=old&&String(previous.part)===String(data.part)?previous.partPrice:p?.price||0;
  }
  if(kind==='cashbook'&&data.type==='Customer receipt'&&!db.prepare("SELECT 1 FROM records WHERE id=? AND kind='jobs'").get(data.job))fail('Choose a valid customer job.');
  return data;
 }
 return{handle,current,requireUser,fail,visible,write,rate};
};
