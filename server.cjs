const http=require('node:http'),fs=require('node:fs'),path=require('node:path');
const {DatabaseSync}=require('node:sqlite');
const base=__dirname,dataDir=process.env.DATA_DIR||base;fs.mkdirSync(dataDir,{recursive:true});
const db=new DatabaseSync(path.join(dataDir,'jeep-village.db'));
db.exec('PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, data TEXT NOT NULL)');
const kinds=['workers','jobs','inventory','bills','cashbook','bookings'];
const auth=require('./auth.cjs')(db);
const server=http.createServer(async(req,res)=>{try{
 res.setHeader('Cache-Control','no-store');
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','same-origin');
 const url=new URL(req.url,'http://localhost');
 if(await auth.handle(req,res,url))return;
 if(url.pathname.startsWith('/api/')&&url.pathname!=='/api/bookings')req.user=auth.requireUser(req);
 if(url.pathname==='/api/bookings'){
  res.setHeader('Content-Type','application/json');
  if(req.method!=='POST'){res.writeHead(405);res.end();return;}
  auth.rate('booking:'+String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',').at(-1),20,60);
  let body='';for await(const chunk of req){body+=chunk;if(body.length>12000)throw Error('Request too large');}
  const input=JSON.parse(body),data={};for(const key of ['customer','phone','email','vehicle','registration','service','date','time','complaint'])data[key]=String(input[key]||'').trim().slice(0,key==='complaint'?2000:150);
  for(const key of ['customer','phone','vehicle','registration','service','date','time'])if(!data[key])throw Error('Please complete all required fields.');
  if(!/^\+?[\d ()-]{7,25}$/.test(data.phone))throw Error('Enter a valid phone number.');
  const today=new Date().toLocaleDateString('en-CA',{timeZone:'Africa/Nairobi'});
  if(!/^\d{4}-\d{2}-\d{2}$/.test(data.date)||data.date<today||Number.isNaN(Date.parse(data.date)))throw Error('Choose today or a future date.');
  if(!['General service','Diagnostics','Engine repair','Brakes & suspension','Electrical repair','Other repair'].includes(data.service)||!['Morning','Afternoon'].includes(data.time))throw Error('Choose a valid service and time preference.');
  if(input.consent!==true)throw Error('Please agree to being contacted about your booking.');
  data.status='New request';data.createdAt=new Date().toISOString();
  const result=db.prepare('INSERT INTO records(kind,data) VALUES(?,?)').run('bookings',JSON.stringify(data));
  res.end(JSON.stringify({ok:true,reference:'JV-'+result.lastInsertRowid}));return;
 }
 if(url.pathname==='/api/job-check'){
  res.setHeader('Content-Type','application/json');
  if(req.method!=='POST'){res.writeHead(405);res.end();return;}
  let body='';for await(const chunk of req){body+=chunk;if(body.length>10000)throw Error('Request too large');}
  const {id,action,checked}=JSON.parse(body),by=req.user.name;
  if(!['finished','collected','paid'].includes(action)||typeof checked!=='boolean'||!String(by||'').trim())throw Error('Choose a valid action and enter your name.');
  db.exec('BEGIN IMMEDIATE');
  try{
   const row=db.prepare("SELECT * FROM records WHERE id=? AND kind='jobs'").get(id);if(!row)throw Error('Job not found');
   const job=JSON.parse(row.data),now=new Date().toISOString();
   if(req.user.role==='technician'&&(String(job.worker)!==String(req.user.worker)||action!=='finished'))auth.fail('You can only complete your assigned jobs.',403);
   if(action==='paid'){
    if(!checked)throw Error('Correct payment entries in Cashbook to change paid status.');
    const receipts=db.prepare("SELECT data FROM records WHERE kind='cashbook'").all().map(r=>JSON.parse(r.data)).filter(r=>r.type==='Customer receipt'&&String(r.job)===String(id));
    const total=Number(job.labour||0)+Number(job.partPrice||0)*Number(job.quantity||0),balance=Math.round((total-receipts.reduce((s,r)=>s+Number(r.amount||0),0))*100)/100;
    if(balance>0)db.prepare('INSERT INTO records(kind,data) VALUES(?,?)').run('cashbook',JSON.stringify({type:'Customer receipt',amount:balance,job:String(id),bill:'',worker:'',date:now.slice(0,10),notes:'Full payment confirmed by '+String(by).trim(),confirmedAt:now}));
   }else{
    job[action]=checked;job[action+'At']=checked?now:null;job[action+'By']=checked?String(by).trim():null;
    if(action==='finished'){job.status=checked?'Completed':'In progress';}
   }
   job.checkHistory=[...(job.checkHistory||[]),{action,checked,by:String(by).trim(),at:now}];
   db.prepare('UPDATE records SET data=? WHERE id=?').run(JSON.stringify(job),id);db.exec('COMMIT');
  }catch(e){db.exec('ROLLBACK');throw e;}
  res.end(JSON.stringify({ok:true}));return;
 }
 if(url.pathname==='/api/records'){
  res.setHeader('Content-Type','application/json');
  if(req.method==='GET'){res.end(JSON.stringify(auth.visible(req.user,db.prepare('SELECT * FROM records').all().map(r=>({id:r.id,kind:r.kind,...JSON.parse(r.data)})))));return;}
  if(req.method!=='POST'){res.writeHead(405);res.end();return;}
  let body='';for await(const chunk of req){body+=chunk;if(body.length>100000)throw Error('Request too large');}
  const {id,kind,...input}=JSON.parse(body);if(!kinds.includes(kind))throw Error('Invalid record type');
  const data=auth.write(req.user,id,kind,input);
  for(const [k,v] of Object.entries(data))if(typeof v==='number'&&(!Number.isFinite(v)||v<0))throw Error('Amounts must be nonnegative');
  if(id){const result=db.prepare('UPDATE records SET data=? WHERE id=? AND kind=?').run(JSON.stringify(data),id,kind);if(!result.changes)throw Error('Record not found');}
  else db.prepare('INSERT INTO records(kind,data) VALUES(?,?)').run(kind,JSON.stringify(data));
  res.end(JSON.stringify({ok:true}));return;
 }
 if(url.pathname==='/'&&process.env.RENDER){res.writeHead(302,{Location:'/book'});res.end();return;}
 if((url.pathname==='/'||url.pathname==='/staff'||url.pathname==='/index.html')&&!auth.current(req)){res.writeHead(302,{Location:'/login'});res.end();return;}
 const file=url.pathname==='/'||url.pathname==='/staff'?'index.html':url.pathname==='/book'?'booking.html':url.pathname==='/login'?'login.html':url.pathname.slice(1);
 if(!['index.html','app.js','style.css','booking.html','booking.js','booking.css','customer-banner.avif','login.html','login.js','staff.js'].includes(file)){res.writeHead(404);res.end();return;}
 res.setHeader('Content-Type',file.endsWith('.avif')?'image/avif':file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(path.join(base,'public',file)));
}catch(e){res.writeHead(e.status||400,{'Content-Type':'application/json'});res.end(JSON.stringify({error:e.message.includes('UNIQUE constraint')?'That email already has an account.':e.message}));}});
server.on('error',e=>{fs.appendFileSync(path.join(base,'startup-error.log'),new Date().toISOString()+' '+e.stack+'\n');console.error(e);process.exit(1)});
server.listen(Number(process.env.PORT||0),process.env.RENDER?'0.0.0.0':'127.0.0.1',()=>{const url='http://127.0.0.1:'+server.address().port;console.log('READY '+url);if(process.argv.includes('--open'))require('node:child_process').spawn('rundll32.exe',['url.dll,FileProtocolHandler',url+(process.argv.includes('--book')?'/book':'/staff')],{detached:true,stdio:'ignore',windowsHide:true}).unref();});

