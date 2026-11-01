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
      select id, invoice_no, invoice_date, invoice_time,
             customer_name, shop_name, bill_maker, customer_phone,
             items, discount, subtotal, grand_total, amount_paid,
             balance, saved_at
      from public.invoices
      order by saved_at desc, updated_at desc
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
      select id, invoice_no, invoice_date, invoice_time,
             customer_name, shop_name, bill_maker, customer_phone,
             items, discount, subtotal, grand_total, amount_paid,
             balance, saved_at
      from public.invoices
      where id = $1
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

    await writeAudit(client,req,existing.rowCount?'invoice.updated':'invoice.created',inv.id,inv.invoiceNo,{grandTotal:inv.grandTotal});
    await client.query('commit');
    res.status(201).json(dbRowToInvoice(result.rows[0]));
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
