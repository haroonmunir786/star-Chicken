require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 3000);

if (!process.env.DATABASE_URL) {
  console.error('Missing DATABASE_URL in .env');
  process.exit(1);
}
if (!process.env.JWT_SECRET) {
  console.error('Missing JWT_SECRET in .env');
  process.exit(1);
}
if (!process.env.APP_PASSWORD) {
  console.error('Missing APP_PASSWORD in .env');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
// This upgrade does not modify invoice, stock, customer or ordering SQL.
// A separate signed role cookie complements the existing outer sc_session login.
const roleSecret = process.env.JWT_SECRET;
// Personal staff PINs are hashed using Node's built-in scrypt and a per-user salt.
function hashStaffPin(pin) {
  const salt = crypto.randomBytes(16).toString('hex');
  const digest = crypto.scryptSync(pin, salt, 64).toString('hex');
  return `scrypt:${salt}:${digest}`;
}
function validStaffPin(pin) { return typeof pin === 'string' && /^[0-9]{6,12}$/.test(pin); }
function verifyStaffPin(pin, stored) {
  if (!validStaffPin(pin) || typeof stored !== 'string') return false;
  const [method, salt, digest] = stored.split(':');
  if (method !== 'scrypt' || !/^[a-f0-9]{32}$/.test(salt||'') || !/^[a-f0-9]{128}$/.test(digest||'')) return false;
  const actual = crypto.scryptSync(pin, salt, 64);
  return crypto.timingSafeEqual(actual, Buffer.from(digest, 'hex'));
}
function staffIdValid(id) { return /^S[A-Z0-9]{2,15}$/.test(id); }
function readRoleIdentity(req) {
  try {
    const d=jwt.verify(req.cookies.sc_role_session||'',roleSecret,{algorithms:['HS256']});
    return d && ['admin','staff'].includes(d.role) ? d : null;
  } catch (_) { return null; }
}
async function requireManagedAdmin(req,res,next) {
  if (readRoleIdentity(req)?.role !== 'admin') return res.status(403).json({error:'Admin access required'});
  next();
}

const loginAttempts = new Map();
function checkRateLimit(req, res, next) {
  const key = `${req.path}:${req.ip}`;
  const now = Date.now();
  let entry = loginAttempts.get(key);
  if (!entry || now - entry.since > 15 * 60 * 1000) entry = {since:now,count:0};
  entry.count += 1;
  loginAttempts.set(key, entry);
  if (entry.count > 20) return res.status(429).json({error:'Too many login attempts. Try again later.'});
  if (loginAttempts.size > 5000) for (const [k,v] of loginAttempts) if (now-v.since>15*60*1000) loginAttempts.delete(k);
  next();
}
function clearLoginAttempts(req) { loginAttempts.delete(`${req.path}:${req.ip}`); }
function verifyCode(input, expected) {
  if (!expected || typeof input !== 'string') return false;
  const x = crypto.createHash('sha256').update(input).digest();
  const y = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(x,y);
}
function roleFromCookie(req) {
  try {
    const data = jwt.verify(req.cookies.sc_role_session || '', roleSecret, {algorithms:['HS256']});
    return data && (data.role==='admin' || data.role==='staff') ? data.role : null;
  } catch (_) { return null; }
}
function adminOnly(req,res,next) {
  if (roleFromCookie(req) !== 'admin') return res.status(403).json({error:'Admin access required'});
  next();
}
const roleCookieOptions = {httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',path:'/'};
app.disable('x-powered-by');
app.use((req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options','SAMEORIGIN');
  next();
});


function signSession() {
  return jwt.sign({ role: 'invoice-user' }, process.env.JWT_SECRET, {
    expiresIn: '7d'
  });
}

async function auth(req, res, next) {
  const token = req.cookies.sc_session;
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    jwt.verify(token, process.env.JWT_SECRET);
    const identity=readRoleIdentity(req);
    if(identity?.role==='staff' && identity.staffId) {
      try {
        const r=await pool.query('select active,session_version from public.pos_staff_users where staff_id=$1',[identity.staffId]);
        if(!r.rowCount||!r.rows[0].active||r.rows[0].session_version!==identity.version) {
          res.clearCookie('sc_role_session',roleCookieOptions);
          return res.status(403).json({error:'Staff account disabled or session expired'});
        }
      } catch(e) { console.error('Staff permission check failed',e);return res.status(503).json({error:'Unable to verify Staff session'}); }
    }
    next();
  } catch (e) {
    res.clearCookie('sc_session');
    return res.status(401).json({ error: 'Session expired' });
  }
}

function cleanInvoice(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Invalid invoice object');
  }

  const id = String(raw.id || '').trim();
  const invoiceNo = String(raw.invoiceNo || '').trim();

  if (!id) throw new Error('Invoice id is required');
  if (!invoiceNo) throw new Error('Invoice number is required');

  const num = (v) => {
    const n = Number(v);
    return Number.isFinite(n) ? n : 0;
  };

  return {
    id,
    invoiceNo,
    date: raw.date ? String(raw.date).slice(0, 10) : null,
    time: raw.time ? String(raw.time) : '',
    customerName: String(raw.customerName || '').trim(),
    shopName: String(raw.shopName || '').trim(),
    billMaker: String(raw.billMaker || '').trim(),
    customerPhone: String(raw.customerPhone || '').trim(),
    items: Array.isArray(raw.items) ? raw.items : [],
    discount: num(raw.discount),
    subTotal: num(raw.subTotal),
    grandTotal: num(raw.grandTotal),
    amountPaid: num(raw.amountPaid),
    balance: num(raw.balance),
    partyType: String(raw.partyType||'').trim(),
    paymentType: String(raw.paymentType||'cash').trim(),
    savedAt: Number(raw.savedAt) || Date.now()
  };
}

function dbRowToInvoice(row) {
  return {
    id: row.id,
    invoiceNo: row.invoice_no,
    date: row.invoice_date ? String(row.invoice_date).slice(0, 10) : '',
    time: row.invoice_time || '',
    customerName: row.customer_name || '',
    shopName: row.shop_name || '',
    billMaker: row.bill_maker || '',
    customerPhone: row.customer_phone || '',
    items: row.items || [],
    discount: Number(row.discount) || 0,
    subTotal: Number(row.subtotal) || 0,
    grandTotal: Number(row.grand_total) || 0,
    amountPaid: Number(row.amount_paid) || 0,
    balance: Number(row.balance) || 0,
    paymentType: row.credit_invoice_id ? 'credit' : 'cash',
    savedAt: Number(row.saved_at) || 0
  };
}

/* ---------- Login ---------- */
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', checkRateLimit, (req, res) => {
  const password = String(req.body?.password || '');
  if (password !== process.env.APP_PASSWORD) {
    return res.status(401).json({ error: 'Incorrect password' });
  }

  clearLoginAttempts(req);
  const token = signSession();
  res.cookie('sc_session', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  res.json({ ok: true });
});

app.post('/logout', (req, res) => {
  res.clearCookie('sc_session');
  res.clearCookie('sc_role_session',roleCookieOptions);
  res.json({ ok: true });
});


/* ---------- Server-verified POS Admin/Staff roles ---------- */
app.get('/api/role/me', auth, async (req,res)=>{
  const identity=readRoleIdentity(req);
  if (!identity) return res.json({role:null});
  if (identity.role==='staff' && identity.staffId) {
    try {
      const r=await pool.query('select staff_id,full_name,active,session_version from public.pos_staff_users where staff_id=$1',[identity.staffId]);
      if (!r.rowCount || !r.rows[0].active || r.rows[0].session_version!==identity.version) {
        res.clearCookie('sc_role_session',roleCookieOptions);
        return res.json({role:null});
      }
      return res.json({role:'staff',staffId:r.rows[0].staff_id,staffName:r.rows[0].full_name});
    } catch(e) { console.error('Staff session validation error',e); return res.status(503).json({error:'Staff login temporarily unavailable'}); }
  }
  res.json({role:identity.role,staffId:null,staffName:null});
});
app.post('/api/role/login', auth, checkRateLimit, async (req,res)=>{
  const adminCode=process.env.POS_ADMIN_CODE;
  const staffCode=process.env.POS_STAFF_CODE;
  if(!adminCode || !staffCode || adminCode===staffCode) return res.status(503).json({error:'POS role credentials not configured on server'});
  // Optional personal Staff ID + PIN. Legacy shared Staff code remains available for safe rollout.
  const staffId=String(req.body?.staffId||'').trim().toUpperCase();
  if(staffId) {
    const pin=String(req.body?.code||'');
    if(!staffIdValid(staffId) || !validStaffPin(pin)) return res.status(401).json({error:'Incorrect Staff ID or PIN'});
    try {
      const r=await pool.query('select staff_id,full_name,pin_hash,active,session_version from public.pos_staff_users where staff_id=$1',[staffId]);
      if(!r.rowCount || !r.rows[0].active || !verifyStaffPin(pin,r.rows[0].pin_hash)) return res.status(401).json({error:'Incorrect Staff ID or PIN'});
      clearLoginAttempts(req);
      const u=r.rows[0];
      const token=jwt.sign({role:'staff',staffId:u.staff_id,version:u.session_version},roleSecret,{expiresIn:'8h',algorithm:'HS256'});
      res.cookie('sc_role_session',token,{...roleCookieOptions,maxAge:8*60*60*1000});
      return res.json({ok:true,role:'staff',staffId:u.staff_id,staffName:u.full_name});
    } catch(e) { console.error('Staff login DB error',e); return res.status(503).json({error:'Staff login not ready. Ask Admin to check Staff setup.'}); }
  }
  const submitted=String(req.body?.code||'');
  const role=verifyCode(submitted,adminCode)?'admin':verifyCode(submitted,staffCode)?'staff':null;
  if(!role)return res.status(401).json({error:'Incorrect access code'});
  clearLoginAttempts(req);
  const token=jwt.sign({role},roleSecret,{expiresIn:'8h',algorithm:'HS256'});
  res.cookie('sc_role_session',token,{...roleCookieOptions,maxAge:8*60*60*1000});
  res.json({ok:true,role});
});
app.post('/api/role/logout', auth, (req,res)=>{res.clearCookie('sc_role_session',roleCookieOptions);res.json({ok:true})});

/* ---------- Admin-only Staff Management (separate table; existing business tables untouched) ---------- */
app.get('/api/staff',auth,requireManagedAdmin,async(req,res)=>{
  try {const r=await pool.query('select staff_id,full_name,active,created_at,updated_at from public.pos_staff_users order by staff_id');res.json(r.rows.map(u=>({staffId:u.staff_id,name:u.full_name,active:u.active,createdAt:u.created_at,updatedAt:u.updated_at})));}
  catch(e){console.error('Staff list error',e);res.status(503).json({error:'Staff table unavailable. Run staff_accounts.sql first.'});}
});
app.post('/api/staff',auth,requireManagedAdmin,async(req,res)=>{
  const id=String(req.body?.staffId||'').trim().toUpperCase(),name=String(req.body?.name||'').trim(),pin=String(req.body?.pin||'');
  if(!staffIdValid(id)||name.length<2||name.length>100||!validStaffPin(pin))return res.status(400).json({error:'Use ID S01–S999..., name 2–100 characters, and a private 6–12 digit PIN'});
  try {await pool.query('insert into public.pos_staff_users(staff_id,full_name,pin_hash) values($1,$2,$3)',[id,name,hashStaffPin(pin)]);res.status(201).json({ok:true});}
  catch(e){if(e.code==='23505')return res.status(409).json({error:'Staff ID already exists'});console.error('Staff creation error',e);res.status(503).json({error:'Could not create Staff account'});}
});
app.patch('/api/staff/:id',auth,requireManagedAdmin,async(req,res)=>{
  const id=String(req.params.id||'').trim().toUpperCase();
  if(!staffIdValid(id))return res.status(400).json({error:'Invalid Staff ID'});
  const name=req.body?.name,active=req.body?.active,pin=req.body?.pin;
  if(name===undefined&&active===undefined&&pin===undefined)return res.status(400).json({error:'No changes supplied'});
  if(name!==undefined&&(typeof name!=='string'||name.trim().length<2||name.trim().length>100))return res.status(400).json({error:'Invalid employee name'});
  if(active!==undefined&&typeof active!=='boolean')return res.status(400).json({error:'Active must be true or false'});
  if(pin!==undefined&&!validStaffPin(pin))return res.status(400).json({error:'PIN must contain 6–12 digits'});
  try {
    const r=await pool.query(`update public.pos_staff_users set
      full_name=coalesce($2,full_name),active=coalesce($3,active),pin_hash=coalesce($4,pin_hash),
      session_version=session_version+case when $3 is not null or $4 is not null then 1 else 0 end,
      updated_at=now() where staff_id=$1 returning staff_id`,
      [id,name===undefined?null:name.trim(),active===undefined?null:active,pin===undefined?null:hashStaffPin(pin)]);
    if(!r.rowCount)return res.status(404).json({error:'Staff account not found'});
    res.json({ok:true});
  }catch(e){console.error('Staff update error',e);res.status(503).json({error:'Could not update Staff account'});}
});


/* Phase 2 audit entries: server-generated identity, never browser-supplied. */
function auditIdentity(req) {
  const i=readRoleIdentity(req);
  if(!i) return {id:'outer-login',name:'Unidentified legacy session'};
  return i.role==='admin' ? {id:'ADMIN',name:'Admin'} :
    i.staffId ? {id:i.staffId,name:null} : {id:'SHARED_STAFF',name:'Shared Staff code'};
}
async function writeAudit(db,req,action,invoiceId,invoiceNo,details={}) {
  const actor=auditIdentity(req);
  await db.query(`insert into public.pos_activity_log
    (actor_id,actor_name,action,invoice_id,invoice_no,details)
    values ($1,coalesce((select full_name from public.pos_staff_users where staff_id=$1),$2),$3,$4,$5,$6::jsonb)`,
    [actor.id,actor.name,action,invoiceId||null,invoiceNo||null,JSON.stringify(details)]);
}
app.get('/api/activity',auth,requireManagedAdmin,async(req,res)=>{
  try {
    const r=await pool.query(`select id,actor_id,actor_name,action,invoice_id,invoice_no,details,created_at
      from public.pos_activity_log order by id desc limit 500`);
    res.json(r.rows);
  } catch(e) {console.error('Activity log read failed',e);res.status(503).json({error:'Activity Log unavailable. Run phase2_activity_log.sql first.'});}
});


/* Phase 3: read-only employee sales summary. Attribution comes from the FIRST
 * server-recorded invoice.created event, never editable bill_maker text.
 * Only invoices still present are counted; deleted invoices are excluded.
 * Legacy invoices without a creation audit are intentionally omitted.
 */
app.get('/api/reports/staff-sales', auth, requireManagedAdmin, async (req,res)=>{
  const from=String(req.query.from||'');
  const to=String(req.query.to||'');
  const validDate=(d)=>/^\d{4}-\d{2}-\d{2}$/.test(d) && !Number.isNaN(Date.parse(d+'T00:00:00Z')) && new Date(d+'T00:00:00Z').toISOString().slice(0,10)===d;
  if(!validDate(from)||!validDate(to)||from>to) return res.status(400).json({error:'Choose a valid From/To date range'});
  try {
    const result=await pool.query(`
      with first_creator as (
        select distinct on (invoice_id) invoice_id, actor_id, actor_name
        from public.pos_activity_log
        where action='invoice.created' and invoice_id is not null
        order by invoice_id, id asc
      ), totals as (
        select c.actor_id, count(*)::int as invoice_count,
               coalesce(sum(i.grand_total),0)::numeric as total_sales
        from public.invoices i
        join first_creator c on c.invoice_id=i.id
        where i.invoice_date >= $1::date and i.invoice_date <= $2::date
        group by c.actor_id
      )
      select t.actor_id as "staffId",
             coalesce(u.full_name, case when t.actor_id='ADMIN' then 'Admin' when t.actor_id='SHARED_STAFF' then 'Shared Staff code' else t.actor_id end) as "staffName",
             t.invoice_count as "invoiceCount", t.total_sales as "totalSales"
      from totals t
      left join public.pos_staff_users u on u.staff_id=t.actor_id
      order by t.total_sales desc, t.actor_id`,[from,to]);
    res.setHeader('Cache-Control','no-store');
    res.json({from,to,rows:result.rows,scope:'Only existing invoices with a Phase 2 creation audit; filtered by invoice date. Current invoice totals reflect any edits.'});
  }catch(e){console.error('Staff sales report failed',e);res.status(503).json({error:'Could not load staff sales report. Verify Phase 2 activity log is available.'});}
});

/* ---------- Health ---------- */
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('select 1');
    res.json({ ok: true, database: true });
  } catch (e) {
    console.error(e);
    res.status(503).json({ ok: false, database: false });
  }
});

/* ---------- Shared Ordering System API ---------- */
/*
  The ordering app has its own single JSON state row in a separate table.
  This deliberately does not read, alter, or delete any invoice records.
*/
app.get('/api/ordering/state', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'select state, updated_at from public.ordering_app_state where id = 1'
    );
    if (!result.rowCount) return res.json({ state: null, updatedAt: null });
    res.json({
      state: result.rows[0].state,
      updatedAt: result.rows[0].updated_at
    });
  } catch (e) {
    console.error('Could not load ordering state:', e);
    res.status(500).json({ error: 'Could not load ordering data. Confirm the ordering_app_state table has been created.' });
  }
});

app.put('/api/ordering/state', auth, async (req, res) => {
  const state = req.body?.state;
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    return res.status(400).json({ error: 'A valid ordering state object is required' });
  }
  if (JSON.stringify(state).length > 1_800_000) {
    return res.status(413).json({ error: 'Ordering data is too large to save' });
  }

  try {
    const result = await pool.query(
      `insert into public.ordering_app_state (id, state, updated_at)
       values (1, $1::jsonb, now())
       on conflict (id) do update
         set state = excluded.state, updated_at = now()
       returning updated_at`,
      [JSON.stringify(state)]
    );
    res.json({ ok: true, updatedAt: result.rows[0].updated_at });
  } catch (e) {
    console.error('Could not save ordering state:', e);
    res.status(500).json({ error: 'Could not save ordering data' });
  }
});


/* ---------- Shared stock / POS inventory state ---------- */
app.get('/api/stock/state', auth, async (req, res) => {
  try { const r = await pool.query('select state, updated_at from public.stock_app_state where id=1'); res.json({state:r.rowCount?r.rows[0].state:null,updatedAt:r.rowCount?r.rows[0].updated_at:null}); }
  catch(e){ console.error('Could not load stock state:',e); res.status(500).json({error:'Could not load stock data. Run schema_additions.sql in Supabase SQL Editor.'}); }
});
app.put('/api/stock/state', auth, async (req, res) => {
  const state=req.body?.state;
  if(!state||typeof state!=='object'||Array.isArray(state)) return res.status(400).json({error:'A valid stock state object is required'});
  if(JSON.stringify(state).length>1_800_000) return res.status(413).json({error:'Stock data is too large to save'});
  try { const r=await pool.query(`insert into public.stock_app_state(id,state,updated_at) values(1,$1::jsonb,now()) on conflict(id) do update set state=excluded.state,updated_at=now() returning updated_at`,[JSON.stringify(state)]);res.json({ok:true,updatedAt:r.rows[0].updated_at}); }
  catch(e){console.error('Could not save stock state:',e);res.status(500).json({error:'Could not save stock data. Run schema_additions.sql in Supabase SQL Editor.'});}
});

/* ---------- Customer details ---------- */
app.get('/api/customers', auth, async (req,res)=>{
  try{const r=await pool.query('select id,name,phone,address,remarks,created_at,updated_at from public.customers order by lower(name),created_at');res.json(r.rows.map(x=>({id:x.id,name:x.name,phone:x.phone||'',address:x.address||'',remarks:x.remarks||'',createdAt:Number(x.created_at)||Date.parse(x.created_at),updatedAt:Number(x.updated_at)||Date.parse(x.updated_at)})));}
  catch(e){console.error('Could not load customers:',e);res.status(500).json({error:'Could not load customers. Run schema_additions.sql in Supabase SQL Editor.'});}
});
app.post('/api/customers', auth, async (req,res)=>{
  const x=req.body||{},id=String(x.id||'').trim(),name=String(x.name||'').trim();
  if(!id||!name)return res.status(400).json({error:'Customer id and name are required'});
  try{const r=await pool.query(`insert into public.customers(id,name,phone,address,remarks,created_at,updated_at) values($1,$2,$3,$4,$5,now(),now()) returning id,name,phone,address,remarks,created_at,updated_at`,[id,name,String(x.phone||''),String(x.address||''),String(x.remarks||'')]);res.status(201).json(r.rows[0]);}
  catch(e){if(e.code==='23505')return res.status(409).json({error:'Customer ID already exists'});console.error('Could not create customer:',e);res.status(500).json({error:'Could not save customer'});}
});
app.put('/api/customers/:id', auth, async (req,res)=>{
  const x=req.body||{},name=String(x.name||'').trim();if(!name)return res.status(400).json({error:'Customer name is required'});
  try{const r=await pool.query(`update public.customers set name=$2,phone=$3,address=$4,remarks=$5,updated_at=now() where id=$1 returning id,name,phone,address,remarks,created_at,updated_at`,[req.params.id,name,String(x.phone||''),String(x.address||''),String(x.remarks||'')]);if(!r.rowCount)return res.status(404).json({error:'Customer not found'});res.json(r.rows[0]);}
  catch(e){console.error('Could not update customer:',e);res.status(500).json({error:'Could not update customer'});}
});
app.delete('/api/customers/:id', auth, adminOnly, async (req,res)=>{try{const r=await pool.query('delete from public.customers where id=$1',[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Customer not found'});res.json({ok:true});}catch(e){console.error('Could not delete customer:',e);res.status(500).json({error:'Could not delete customer'});}});


/* ---------- Party Customer Credit Ledger (Admin + Staff) ----------
   Only credit invoices posted AFTER installation have entries here.
   Existing invoices are never imported and are considered settled.
*/
app.get('/api/credit/ledger',auth,async(req,res)=>{
  if(!readRoleIdentity(req))return res.status(403).json({error:'Sign in as Staff or Admin'});
  try{
    const a=await pool.query(`select invoice_id,invoice_no,customer_name,grand_total,amount_paid,outstanding_at_sale,prepared_by,created_at
      from public.sc_credit_invoices order by created_at desc`);
    const b=await pool.query(`select id,customer_name,amount,method,note,received_by,created_at
      from public.sc_credit_payments order by created_at desc`);
    const accounts=new Map();
    function get(name){const key=String(name).trim().toLowerCase();if(!accounts.has(key))accounts.set(key,{customerName:name,creditSales:0,received:0,outstanding:0});return accounts.get(key)}
    for(const r of a.rows){let x=get(r.customer_name);x.creditSales+=Number(r.grand_total);x.received+=Number(r.amount_paid);x.outstanding+=Number(r.outstanding_at_sale)}
    for(const r of b.rows){let x=get(r.customer_name);x.received+=Number(r.amount);x.outstanding-=Number(r.amount)}
    const round=n=>Math.round(n*100)/100;
    res.setHeader('Cache-Control','no-store');
    res.json({accounts:[...accounts.values()].map(a=>({...a,creditSales:round(a.creditSales),received:round(a.received),outstanding:round(a.outstanding)})).sort((a,b)=>a.customerName.localeCompare(b.customerName)),
      invoices:a.rows.map(r=>({invoiceId:r.invoice_id,invoiceNo:r.invoice_no,customerName:r.customer_name,grandTotal:Number(r.grand_total),amountPaid:Number(r.amount_paid),outstandingAtSale:Number(r.outstanding_at_sale),preparedBy:r.prepared_by,createdAt:Date.parse(r.created_at)})),
      payments:b.rows.map(r=>({id:r.id,customerName:r.customer_name,amount:Number(r.amount),method:r.method,note:r.note,receivedBy:r.received_by,createdAt:Date.parse(r.created_at)}))});
  }catch(e){console.error('Credit ledger read failed',e);res.status(503).json({error:'Credit ledger unavailable. Install credit_ledger.sql first.'});}
});
app.post('/api/credit/payments',auth,async(req,res)=>{
  const identity=readRoleIdentity(req);
  if(!identity)return res.status(403).json({error:'Staff or Admin login required'});
  const name=String(req.body?.customerName||'').replace(/\s+/g,' ').trim();
  const amount=Number(req.body?.amount);
  const method=String(req.body?.method||'Cash');
  const note=String(req.body?.note||'').trim();
  if(!name||name.length>150||!Number.isFinite(amount)||amount<=0||Math.round(amount*100)!==amount*100||amount>1e9||!['Cash','Bank Transfer','Other'].includes(method)||note.length>180)
    return res.status(400).json({error:'Invalid payment details'});
  const client=await pool.connect();
  try{
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock(hashtext(lower($1)))',[name]);
    const credit=await client.query(`select coalesce(sum(outstanding_at_sale),0)::numeric as due,min(customer_name) as canonical
      from public.sc_credit_invoices where lower(trim(customer_name))=lower($1)`,[name]);
    const paid=await client.query(`select coalesce(sum(amount),0)::numeric as amount from public.sc_credit_payments
      where lower(trim(customer_name))=lower($1)`,[name]);
    const outstanding=Math.round((Number(credit.rows[0].due)-Number(paid.rows[0].amount))*100)/100;
    if(!credit.rows[0].canonical||amount>outstanding+0.005){await client.query('rollback');return res.status(409).json({error:'Customer credit balance is insufficient. Refresh ledger.'});}
    const by=identity.role==='admin'?'Admin':(identity.staffId||'Shared Staff');
    const id=crypto.randomUUID();
    await client.query(`insert into public.sc_credit_payments(id,customer_name,amount,method,note,received_by)
      values($1,$2,$3,$4,$5,$6)`,[id,credit.rows[0].canonical,amount,method,note,by]);
    await writeAudit(client,req,'credit.payment.received',id,'',{customerName:credit.rows[0].canonical,amount,method});
    await client.query('commit');
    res.status(201).json({ok:true,paymentId:id,outstanding:Math.round((outstanding-amount)*100)/100});
  }catch(e){await client.query('rollback');console.error('Credit payment save failed',e);res.status(503).json({error:'Payment not saved. Check ledger installation.'});}
  finally{client.release()}
});

/* ---------- Invoice numbering ---------- */
// Preview-only: shows what the NEXT number would be, without consuming it.
// The number is only actually assigned (atomically) when an invoice is saved.
app.get('/api/invoices/next-number', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `select last_number + 1 as next from public.invoice_counters where prefix = $1`,
      ['SC-PC']
    );
    const next = result.rowCount ? result.rows[0].next : 1001;
    res.json({ invoiceNo: `SC-PC-${next}` });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not get next invoice number' });
  }
});

/* ---------- Invoice API ---------- */
app.get('/api/invoices', auth, async (req, res) => {
  try {
    const result = await pool.query(`
      select i.id, i.invoice_no, i.invoice_date, i.invoice_time,
             i.customer_name, i.shop_name, i.bill_maker, i.customer_phone,
             i.items, i.discount, i.subtotal, i.grand_total, i.amount_paid,
             i.balance, i.saved_at, c.invoice_id as credit_invoice_id
      from public.invoices i
      left join public.sc_credit_invoices c on c.invoice_id=i.id
      order by i.saved_at desc, i.updated_at desc
    `);
    res.json(result.rows.map(dbRowToInvoice));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not load invoices' });
  }
});

app.get('/api/invoices/:id', auth, async (req, res) => {
  try {
    const result = await pool.query(`
      select i.id, i.invoice_no, i.invoice_date, i.invoice_time,
             i.customer_name, i.shop_name, i.bill_maker, i.customer_phone,
             i.items, i.discount, i.subtotal, i.grand_total, i.amount_paid,
             i.balance, i.saved_at, c.invoice_id as credit_invoice_id
      from public.invoices i
      left join public.sc_credit_invoices c on c.invoice_id=i.id
      where i.id = $1
    `, [req.params.id]);

    if (!result.rowCount) return res.status(404).json({ error: 'Invoice not found' });
    res.json(dbRowToInvoice(result.rows[0]));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not load invoice' });
  }
});

app.post('/api/invoices', auth, async (req, res) => {
  let inv;
  try {
    inv = cleanInvoice(req.body);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const client = await pool.connect();
  try {
    await client.query('begin');

    const existing = await client.query(
      'select invoice_no, bill_maker from public.invoices where id = $1',
      [inv.id]
    );

    if (existing.rowCount) {
      // Once a new credit invoice is posted, keep its invoice/ledger consistent.
      const protectedCredit=await client.query('select 1 from public.sc_credit_invoices where invoice_id=$1',[inv.id]);
      if(protectedCredit.rowCount){await client.query('rollback');return res.status(409).json({error:'Credit invoice is locked to protect the ledger; contact Admin for adjustments.'});}
      inv.invoiceNo = existing.rows[0].invoice_no;
      // Preserve original preparer on edits: older invoices are not reassigned.
      inv.billMaker = existing.rows[0].bill_maker || '';
    } else {
      const identity=readRoleIdentity(req);
      if (identity?.role==='staff' && identity.staffId) {
        const person=await client.query('select full_name from public.pos_staff_users where staff_id=$1 and active=true',[identity.staffId]);
        if (!person.rowCount) {await client.query('rollback');return res.status(403).json({error:'Valid employee session required'});}
        inv.billMaker=person.rows[0].full_name;
      } else if(identity?.role==='admin') inv.billMaker='Admin';
      else if(identity?.role==='staff') inv.billMaker='Shared Staff';
      else {await client.query('rollback');return res.status(403).json({error:'Please sign in to POS before saving an invoice'});}
    }
    if(!existing.rowCount) {
      if(!['cash','credit'].includes(inv.paymentType)) {await client.query('rollback');return res.status(400).json({error:'Choose Cash or Credit'});}
      if(inv.paymentType==='credit' && inv.partyType!=='party') {await client.query('rollback');return res.status(400).json({error:'Credit only allowed for Party Customers'});}
      if(!Number.isFinite(inv.grandTotal)||inv.grandTotal<0||inv.amountPaid<0||inv.amountPaid>inv.grandTotal+0.005){await client.query('rollback');return res.status(400).json({error:'Invalid amount paid'});}
      // Explicit new invoices with a category must follow full cash settlement.
      if(inv.partyType && inv.paymentType==='cash' && Math.abs(inv.grandTotal-inv.amountPaid)>0.005){await client.query('rollback');return res.status(400).json({error:'Cash invoices must be fully paid'});}
      // Names of Star Chicken branches must never be treated as credit customers.
      const branches=['Hatchery','Kasur','Gajjumatta','Gajjumata','Mustafabad','Gulshan Ravi','Murghzar','Link Road'];
      if(inv.paymentType==='credit' && branches.some(b=>b.toLowerCase()===inv.shopName.toLowerCase())){await client.query('rollback');return res.status(400).json({error:'Star Chicken branches are cash-only'});}
    }
    if (!existing.rowCount) {
      const counterResult = await client.query(
        `update public.invoice_counters
         set last_number = last_number + 1
         where prefix = $1
         returning last_number`,
        ['SC-PC']
      );
      const next = counterResult.rows[0].last_number;
      inv.invoiceNo = `SC-PC-${next}`;
    }

    const result = await client.query(`
      insert into public.invoices
      (id, invoice_no, invoice_date, invoice_time, customer_name, shop_name,
       bill_maker, customer_phone, items, discount, subtotal, grand_total,
       amount_paid, balance, saved_at)
      values
      ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14,$15)
      on conflict (id) do update set
        invoice_no = excluded.invoice_no,
        invoice_date = excluded.invoice_date,
        invoice_time = excluded.invoice_time,
        customer_name = excluded.customer_name,
        shop_name = excluded.shop_name,
        bill_maker = excluded.bill_maker,
        customer_phone = excluded.customer_phone,
        items = excluded.items,
        discount = excluded.discount,
        subtotal = excluded.subtotal,
        grand_total = excluded.grand_total,
        amount_paid = excluded.amount_paid,
        balance = excluded.balance,
        saved_at = excluded.saved_at
      returning id, invoice_no, invoice_date, invoice_time,
                customer_name, shop_name, bill_maker, customer_phone,
                items, discount, subtotal, grand_total, amount_paid,
                balance, saved_at
    `, [
      inv.id, inv.invoiceNo, inv.date, inv.time, inv.customerName,
      inv.shopName, inv.billMaker, inv.customerPhone, JSON.stringify(inv.items),
      inv.discount, inv.subTotal, inv.grandTotal, inv.amountPaid,
      inv.balance, inv.savedAt
    ]);

    if(!existing.rowCount && inv.paymentType==='credit') {
      const owed=Math.round((inv.grandTotal-inv.amountPaid)*100)/100;
      if(owed>0) {
        const creditName=inv.shopName.replace(/\s+/g,' ').trim();
        if(!creditName) {await client.query('rollback');return res.status(400).json({error:'Choose Party Customer for credit'});}
        await client.query('select pg_advisory_xact_lock(hashtext(lower($1)))',[creditName]);
        await client.query(`insert into public.sc_credit_invoices(invoice_id,invoice_no,customer_name,grand_total,amount_paid,outstanding_at_sale,prepared_by)
          values($1,$2,$3,$4,$5,$6,$7)`,[inv.id,inv.invoiceNo,creditName,inv.grandTotal,inv.amountPaid,owed,inv.billMaker]);
      }
    }
    await writeAudit(client,req,existing.rowCount?'invoice.updated':'invoice.created',inv.id,inv.invoiceNo,{grandTotal:inv.grandTotal});
    await client.query('commit');
    res.status(201).json({...dbRowToInvoice(result.rows[0]),paymentType:existing.rowCount?'cash':inv.paymentType});
  } catch (e) {
    await client.query('rollback');
    console.error(e);
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Duplicate invoice number or ID' });
    }
    res.status(500).json({ error: 'Could not save invoice' });
  } finally {
    client.release();
  }
});

app.delete('/api/invoices/:id', auth, adminOnly, async (req, res) => {
  // Do not allow deletion to orphan credit ledger records.
  try {const credit=await pool.query('select 1 from public.sc_credit_invoices where invoice_id=$1',[req.params.id]);
    if(credit.rowCount)return res.status(409).json({error:'Credit invoice has a ledger entry and cannot be deleted'});
  } catch(e){console.error('Credit deletion guard error',e);return res.status(503).json({error:'Could not verify credit ledger; invoice not deleted'});}

  const client=await pool.connect();
  try {
    await client.query('begin');
    const found=await client.query('select invoice_no from public.invoices where id=$1 for update',[req.params.id]);
    if(!found.rowCount) {await client.query('rollback');return res.status(404).json({error:'Invoice not found'});}
    await client.query('delete from public.invoices where id=$1',[req.params.id]);
    await writeAudit(client,req,'invoice.deleted',req.params.id,found.rows[0].invoice_no);
    await client.query('commit');
    res.status(204).end();
  } catch(e) {
    try{await client.query('rollback')}catch(_){}
    console.error('Invoice deletion failed',e);
    res.status(500).json({error:'Could not delete invoice'});
  } finally {client.release();}
});

/* ---------- One-time migration endpoint ---------- */
app.post('/api/invoices/bulk', auth, adminOnly, async (req, res) => {
  const invoices = Array.isArray(req.body?.invoices) ? req.body.invoices : [];
  if (!invoices.length) return res.json({ uploaded: 0 });

  const client = await pool.connect();
  let uploaded = 0;
  try {
    await client.query('begin');

    for (const raw of invoices) {
      const inv = cleanInvoice(raw);
      await client.query(`
        insert into public.invoices
        (id, invoice_no, invoice_date, invoice_time, customer_name, shop_name,
         bill_maker, customer_phone, items, discount, subtotal, grand_total,
         amount_paid, balance, saved_at)
        values
        ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14,$15)
        on conflict (id) do update set
          invoice_no = excluded.invoice_no,
          invoice_date = excluded.invoice_date,
          invoice_time = excluded.invoice_time,
          customer_name = excluded.customer_name,
          shop_name = excluded.shop_name,
          bill_maker = excluded.bill_maker,
          customer_phone = excluded.customer_phone,
          items = excluded.items,
          discount = excluded.discount,
          subtotal = excluded.subtotal,
          grand_total = excluded.grand_total,
          amount_paid = excluded.amount_paid,
          balance = excluded.balance,
          saved_at = excluded.saved_at
      `, [
        inv.id, inv.invoiceNo, inv.date, inv.time, inv.customerName,
        inv.shopName, inv.billMaker, inv.customerPhone, JSON.stringify(inv.items),
        inv.discount, inv.subTotal, inv.grandTotal, inv.amountPaid,
        inv.balance, inv.savedAt
      ]);
      uploaded++;
    }

    let maxNum = 0;
    for (const raw of invoices) {
      const n = parseInt(String(raw.invoiceNo || '').replace(/\D/g, ''), 10);
      if (Number.isFinite(n) && n > maxNum) maxNum = n;
    }
    if (maxNum > 0) {
      await client.query(
        `update public.invoice_counters
         set last_number = greatest(last_number, $1)
         where prefix = $2`,
        [maxNum, 'SC-PC']
      );
    }

    await client.query('commit');
    res.json({ uploaded });
  } catch (e) {
    await client.query('rollback');
    console.error(e);
    res.status(500).json({ error: 'Bulk migration failed after ' + uploaded + ' invoice(s)' });
  } finally {
    client.release();
  }
});

/* ---------- Admin-only invoice Bluetooth print tracking ---------- */
// Separate append-only request log. Never updates business invoices or counters.
app.get('/api/reports/print-tracking', auth, requireManagedAdmin, async (req, res) => {
  const from=String(req.query.from||''),to=String(req.query.to||'');
  const validDate=d=>/^\d{4}-\d{2}-\d{2}$/.test(d) && !Number.isNaN(Date.parse(d+'T00:00:00Z')) && new Date(d+'T00:00:00Z').toISOString().slice(0,10)===d;
  if(!validDate(from)||!validDate(to)||from>to) return res.status(400).json({error:'Select a valid From and To invoice date'});
  try {
    const r=await pool.query(`
      with first_creator as (
        select distinct on (invoice_id) invoice_id,actor_id,actor_name
        from public.pos_activity_log
        where action='invoice.created' and invoice_id is not null
        order by invoice_id,id asc
      ), print_totals as (
        select invoice_id,count(*)::int as requests,
               min(requested_at) as first_requested_at,
               max(requested_at) as last_requested_at,
               count(receipt_fetched_at)::int as app_fetches
        from public.pos_print_requests group by invoice_id
      ), last_request as (
        select distinct on (invoice_id) invoice_id,actor_id,actor_name
        from public.pos_print_requests
        order by invoice_id,requested_at desc,id desc
      )
      select i.id as "invoiceId",i.invoice_no as "invoiceNo",
             to_char(i.invoice_date,'YYYY-MM-DD') as "invoiceDate",
             i.customer_name as "customerName",
             i.bill_maker as "billMaker",
             coalesce(c.actor_id,'') as "creatorId",
             coalesce(u.full_name,c.actor_name,i.bill_maker,'Unknown') as "creatorName",
             coalesce(p.requests,0) as "requests",
             coalesce(p.app_fetches,0) as "appFetches",
             p.first_requested_at as "firstRequestedAt",
             p.last_requested_at as "lastRequestedAt",
             coalesce(l.actor_id,'') as "lastRequestedById",
             coalesce(l.actor_name,'') as "lastRequestedByName"
      from public.invoices i
      left join first_creator c on c.invoice_id=i.id
      left join public.pos_staff_users u on u.staff_id=c.actor_id
      left join print_totals p on p.invoice_id=i.id
      left join last_request l on l.invoice_id=i.id
      where i.invoice_date >= $1::date and i.invoice_date <= $2::date
      order by i.invoice_date desc,i.invoice_no desc`,[from,to]);
    res.setHeader('Cache-Control','no-store');
    res.json({from,to,rows:r.rows,scope:'Print tracking starts after installation. Print requested is not proof that paper was printed.'});
  } catch(e) {
    console.error('Print tracking report failed:',e);
    res.status(503).json({error:'Unable to load Print Tracking Report. Install print_tracking.sql first.'});
  }
});

/* ---------- Short-lived Bluetooth Print receipts (read-only) ---------- */
// The printer app fetches a receipt without sharing the browser's login cookies.
// Only a signed, short-lived token for ONE saved invoice can access this route.
const bluetoothPrintAudience = 'star-chicken-bluetooth-print';
const bluetoothPrintIssuer = 'star-chicken-pos';

function bluetoothText(content, options = {}) {
  return {
    type: 0,
    content: String(content == null ? '' : content).replace(/[\r\n\t]+/g, ' ').slice(0, 250),
    bold: options.bold ? 1 : 0,
    align: options.align == null ? 0 : options.align,
    format: options.format == null ? 0 : options.format
  };
}
function bluetoothMoney(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2}) : '0.00';
}
function bluetoothPlain(value, maxLength = 100) {
  return String(value == null ? '' : value).replace(/[\r\n\t]+/g, ' ').replace(/[<>]/g, '').trim().slice(0, maxLength);
}
function bluetoothReceipt(row) {
  const records = [];
  const add = (value, options) => records.push(bluetoothText(value, options));
  const rule = () => add('--------------------------------');
  add('STAR CHICKEN', {bold:true,align:1,format:2});
  add('SAFE - HEALTHY - HYGIENIC', {align:1});
  rule();
  add('Invoice: ' + bluetoothPlain(row.invoice_no, 60), {bold:true});
  const invoiceDate = row.invoice_date instanceof Date ? row.invoice_date.toISOString().slice(0, 10) : bluetoothPlain(row.invoice_date, 20);
  add('Date: ' + invoiceDate + '  ' + bluetoothPlain(row.invoice_time, 30));
  if (row.customer_name) add('Customer: ' + bluetoothPlain(row.customer_name));
  if (row.shop_name) add('Party: ' + bluetoothPlain(row.shop_name));
  if (row.customer_phone) add('Phone: ' + bluetoothPlain(row.customer_phone, 40));
  rule();
  add('ITEMS', {bold:true});
  const items = Array.isArray(row.items) ? row.items.slice(0, 150) : [];
  items.forEach((item, index) => {
    add((index + 1) + '. ' + bluetoothPlain(item.name || item.product || 'Item', 85), {bold:true});
    const qty = bluetoothPlain(item.qty == null ? '1' : item.qty, 18);
    const weight = Number(item.weight);
    const units = weight > 0 && Number.isFinite(weight) ? '  Wt ' + weight.toFixed(2) + 'kg' : '';
    add('Qty ' + qty + units + '  @ Rs ' + bluetoothMoney(item.rate));
    add('Rs ' + bluetoothMoney(item.amount), {align:2});
  });
  rule();
  add('Sub Total: Rs ' + bluetoothMoney(row.subtotal));
  add('Discount: Rs ' + bluetoothMoney(row.discount));
  add('TOTAL: Rs ' + bluetoothMoney(row.grand_total), {bold:true,format:1});
  add('Paid: Rs ' + bluetoothMoney(row.amount_paid));
  add('Balance: Rs ' + bluetoothMoney(row.balance), {bold:true});
  rule();
  if (row.bill_maker) add('Prepared By: ' + bluetoothPlain(row.bill_maker, 80));
  add('Thank you for choosing Star Chicken!', {align:1});
  add(' ', {align:0});
  add(' ', {align:0});
  // PHP's JSON_FORCE_OBJECT produces an object with numeric keys, not an array.
  return Object.fromEntries(records.map((record, index) => [String(index), record]));
}

// Browser-only: the requester must have both the outer session and a POS role.
app.post('/api/print/bluetooth/link', auth, async (req, res) => {
  if (!readRoleIdentity(req)) return res.status(403).json({error:'Please log in to Star Chicken POS'});
  const id = req.body && typeof req.body.id === 'string' ? req.body.id.trim() : '';
  if (!id || id.length > 150) return res.status(400).json({error:'Saved invoice ID required'});
  try {
    const found = await pool.query('select id,invoice_no from public.invoices where id=$1',[id]);
    if (!found.rowCount) return res.status(404).json({error:'This invoice is not saved in the cloud. Save it first.'});
    const actor=auditIdentity(req);
    // Record a print request BEFORE returning the link. The app can fail to print,
    // so this is intentionally not called a confirmed printed receipt.
    const logged=await pool.query(`insert into public.pos_print_requests
      (invoice_id,invoice_no,actor_id,actor_name)
      values ($1,$2,$3,coalesce((select full_name from public.pos_staff_users where staff_id=$3),$4))
      returning id`,[id,found.rows[0].invoice_no,actor.id,actor.name]);
    const token = jwt.sign({purpose:'bluetooth-receipt',invoiceId:id,printRequestId:String(logged.rows[0].id)}, roleSecret, {
      algorithm:'HS256',expiresIn:'3m',audience:bluetoothPrintAudience,issuer:bluetoothPrintIssuer
    });
    res.setHeader('Cache-Control','no-store');
    res.json({path:'/api/print/bluetooth/receipt/'+encodeURIComponent(token),expiresInSeconds:180});
  } catch (e) {
    console.error('Could not create Bluetooth print link:',e);
    res.status(503).json({error:'Could not prepare receipt for printing'});
  }
});

// Printer-app-only: no normal browser cookie required. This cannot list invoices.
app.get('/api/print/bluetooth/receipt/:token', async (req, res) => {
  res.setHeader('Cache-Control','no-store, private');
  res.setHeader('X-Robots-Tag','noindex, nofollow');
  let payload;
  try {
    payload = jwt.verify(req.params.token, roleSecret, {
      algorithms:['HS256'],audience:bluetoothPrintAudience,issuer:bluetoothPrintIssuer
    });
    if (payload.purpose !== 'bluetooth-receipt' || typeof payload.invoiceId !== 'string') throw new Error('Invalid purpose');
  } catch (_) { return res.status(403).json({error:'Print link expired or invalid. Generate a new link in POS.'}); }
  try {
    const found = await pool.query(`select invoice_no, invoice_date, invoice_time, customer_name,
      shop_name, customer_phone, bill_maker, items, discount, subtotal, grand_total,
      amount_paid, balance from public.invoices where id=$1`,[payload.invoiceId]);
    if (!found.rowCount) return res.status(404).json({error:'Invoice no longer exists'});
    // This means the app fetched the JSON, NOT that the printer produced paper.
    // Printing should still work if this secondary status update fails.
    if (/^\d+$/.test(String(payload.printRequestId||''))) {
      try {
        await pool.query(`update public.pos_print_requests
          set receipt_fetched_at=coalesce(receipt_fetched_at,now())
          where id=$1 and invoice_id=$2`,[payload.printRequestId,payload.invoiceId]);
      } catch(logError) {console.error('Print receipt fetch tracking failed:',logError);}
    }
    res.setHeader('Content-Type','application/json; charset=utf-8');
    return res.json(bluetoothReceipt(found.rows[0]));
  } catch (e) {
    console.error('Bluetooth print receipt failed:',e);
    return res.status(503).json({error:'Could not prepare invoice receipt'});
  }
});

/* ---------- Serve protected front-end apps ---------- */
app.get('/', auth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'palmcity.html'));
});

app.get('/star-chicken-orders.html', auth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'star-chicken-orders.html'));
});

app.get('/star-chicken-stock-management.html', auth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'star-chicken-stock-management.html'));
});

app.use((req, res) => {
  res.status(404).send('Not found');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Star Chicken Invoice App running on http://localhost:${PORT}`);
});
