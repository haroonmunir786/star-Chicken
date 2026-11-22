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
        and not exists(select 1 from public.sc_credit_voids v where v.invoice_id=i.id)
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



/* ---------- Cloud Price List: Admin-managed, enforced at invoice save ---------- */
const SC_PRICE_SOURCE_URL='https://lahore.punjab.gov.pk/poultry-rate-list';
const scPriceEventClients=new Set();
let scPriceEventVersion=0;
function scNotifyPriceChanged(){
  scPriceEventVersion++;
  for(const response of scPriceEventClients){try{response.write('event: price-change\ndata: '+JSON.stringify({version:scPriceEventVersion})+'\n\n');}catch(_){scPriceEventClients.delete(response);}}
}
app.get('/api/prices/events',auth,(req,res)=>{
  if(!readRoleIdentity(req))return res.status(403).end();
  res.status(200).set({'Content-Type':'text/event-stream','Cache-Control':'no-cache, no-transform','Connection':'keep-alive','X-Accel-Buffering':'no'});
  res.flushHeaders?.();res.write('event: connected\ndata: {}\n\n');
  scPriceEventClients.add(res);
  const heartbeat=setInterval(()=>{try{res.write(': ping\n\n')}catch(_){}},25000);
  req.on('close',()=>{clearInterval(heartbeat);scPriceEventClients.delete(res)});
});
function scPriceValue(row,base){
  const factor=row.pricing_type==='factor';
  const n=Number(factor?row.factor:row.fixed_price);
  if(!Number.isFinite(n)||n<=0)return null;
  return Math.round((factor?Number(base)*n:n)*100)/100;
}
async function scGetPrices(db){
  const [s,p]=await Promise.all([
    db.query('select base_rate,rate_date,source_name,updated_at,updated_by,enforcement_enabled from public.sc_price_settings where id=1'),
    db.query('select p.product_name,p.pricing_type,p.kg_per_packet,p.fixed_price,p.factor,p.updated_at,p.updated_by from public.sc_price_products p join public.sc_product_catalog c on c.product_name=p.product_name where c.is_active=true order by p.product_name')
  ]);
  if(!s.rowCount)throw new Error('Price setup missing: run price_list.sql');
  const settings=s.rows[0],base=Number(settings.base_rate);
  return {enforced:!!settings.enforcement_enabled,baseRate:base,rateDate:settings.rate_date instanceof Date?settings.rate_date.toISOString().slice(0,10):String(settings.rate_date).slice(0,10),sourceName:settings.source_name,sourceUrl:SC_PRICE_SOURCE_URL,updatedAt:settings.updated_at,updatedBy:settings.updated_by,
    products:p.rows.map(x=>({name:x.product_name,type:x.pricing_type,packKg:Number(x.kg_per_packet),fixed:x.fixed_price===null?null:Number(x.fixed_price),factor:x.factor===null?null:Number(x.factor),rate:scPriceValue(x,base)}))};
}
app.get('/api/prices',auth,async(req,res)=>{
  if(!readRoleIdentity(req))return res.status(403).json({error:'POS login required'});
  try{res.set('Cache-Control','no-store');res.json(await scGetPrices(pool));}
  catch(e){console.error('Prices unavailable',e);res.status(503).json({error:'Price List not ready. Admin must run price_list.sql in Supabase.'});}
});
app.put('/api/prices/enforcement',auth,adminOnly,async(req,res)=>{
  const enabled=req.body?.enabled;if(typeof enabled!=='boolean')return res.status(400).json({error:'Invalid activation setting'});
  const client=await pool.connect();
  try{await client.query('begin');
    if(enabled){
      const found=await client.query(`select count(*)::int as cnt from public.sc_price_products where (pricing_type='fixed' and fixed_price is not null) or (pricing_type='factor' and factor is not null)`);
      if(!found.rows[0].cnt){await client.query('rollback');return res.status(400).json({error:'Configure at least one product price first'});}
    }
    await client.query('update public.sc_price_settings set enforcement_enabled=$1,updated_at=now(),updated_by=$2 where id=1',[enabled,auditIdentity(req).id]);
    await writeAudit(client,req,enabled?'prices.enforcement.enabled':'prices.enforcement.disabled',null,null,{});
    await client.query('commit');scNotifyPriceChanged();res.json({ok:true,enabled});
  }catch(e){await client.query('rollback').catch(()=>{});console.error(e);res.status(503).json({error:'Cannot change pricing activation'});}finally{client.release();}
});
app.put('/api/prices/base',auth,adminOnly,async(req,res)=>{
  const base=Number(req.body?.baseRate),day=String(req.body?.rateDate||'');
  if(!Number.isFinite(base)||base<=0||base>100000||!/^\d{4}-\d{2}-\d{2}$/.test(day)||Number.isNaN(Date.parse(day)))return res.status(400).json({error:'Provide a valid announced rate and published date'});
  const client=await pool.connect();
  try{await client.query('begin');
    await client.query('update public.sc_price_settings set base_rate=$1,rate_date=$2,updated_at=now(),updated_by=$3 where id=1',[base,day,auditIdentity(req).id]);
    await writeAudit(client,req,'prices.base.approved',null,null,{baseRate:base,rateDate:day,category:'Lahore live broiler wholesale, second row'});
    await client.query('commit');scNotifyPriceChanged();res.json({ok:true});
  }catch(e){await client.query('rollback').catch(()=>{});console.error(e);res.status(503).json({error:'Could not save approved base rate'});}finally{client.release();}
});
app.put('/api/prices/product',auth,adminOnly,async(req,res)=>{
  const name=String(req.body?.name||'');const type=String(req.body?.type||'');const value=Number(req.body?.value);
  if(!name||!['fixed','factor'].includes(type)||!Number.isFinite(value)||value<=0||value>1000000)return res.status(400).json({error:'Enter a valid fixed rate or factor'});
  const client=await pool.connect();
  try{await client.query('begin');
    const old=await client.query('select pricing_type from public.sc_price_products where product_name=$1 for update',[name]);
    if(!old.rowCount){await client.query('rollback');return res.status(404).json({error:'Unknown catalog product'});}
    // Admin may switch any product between fixed and factor pricing.
    // Clear the inactive column to satisfy the existing sc_price_products CHECK constraint.
    // Historical invoices store their own rates, so they are not repriced.
    await client.query(`update public.sc_price_products
      set pricing_type=$2,fixed_price=$3,factor=$4,updated_at=now(),updated_by=$5
      where product_name=$1`,[name,type,type==='fixed'?value:null,type==='factor'?value:null,auditIdentity(req).id]);
    await writeAudit(client,req,'prices.product.updated',null,null,{product:name,oldType:old.rows[0].pricing_type,type,value});
    await client.query('commit');scNotifyPriceChanged();res.json({ok:true});
  }catch(e){await client.query('rollback').catch(()=>{});console.error(e);res.status(503).json({error:'Price update failed'});}finally{client.release();}
});
/* On NEW invoices, trust only catalog prices held in Supabase, never the browser's rate/weight/amount. */
async function scEnforceNewInvoicePrices(client,inv,identity){
  const priceList=await scGetPrices(client);
  // Archived products cannot be sold on NEW invoices, even during Setup Mode.
  // Existing invoice edits are handled separately and keep their historical items.
  if(!Array.isArray(inv.items)||!inv.items.length)throw new Error('Add at least one product');
  const allowed=new Set(priceList.products.map(x=>x.name));
  for(const x of inv.items)if(!allowed.has(String(x.name||'').trim()))throw new Error('Product is archived or not in the approved catalog: '+String(x.name||''));
  // Party Customers negotiate their own Qty, KG and Rate, independent of Price Lock.
  // A Star Chicken branch cannot bypass the approved prices by changing partyType in the browser.
  const starBranches=['Hatchery','Kasur','Gajjumatta','Gajjumata','Mustafabad','Gulshan Ravi','Murghzar','Link Road'];
  const isStarBranch=starBranches.some(x=>x.toLowerCase()===String(inv.shopName||'').trim().toLowerCase());
  if(inv.partyType==='party' && isStarBranch)throw new Error('Star Chicken branches must use the approved Price List');
  if(inv.partyType==='party'){
    if(inv.items.length>150)throw new Error('Too many invoice products');
    const repriced=[];let subtotal=0;
    for(const x of inv.items){
      const name=String(x.name||'').trim(),qty=Number(x.qty),weight=Number(x.weight),rate=Number(x.rate);
      if(!name||!Number.isFinite(qty)||qty<=0||qty>100000||Math.abs(qty*1000-Math.round(qty*1000))>0.000001)throw new Error('Invalid quantity for '+name);
      if(x.weight===null||x.weight===undefined||x.weight===''||!Number.isFinite(weight)||weight<=0||weight>100000||Math.abs(weight*1000-Math.round(weight*1000))>0.000001)throw new Error('Invalid weight for '+name);
      if(x.rate===null||x.rate===undefined||x.rate===''||!Number.isFinite(rate)||rate<=0||rate>1000000||Math.abs(rate*100-Math.round(rate*100))>0.000001)throw new Error('Invalid rate for '+name);
      const amount=Math.round(weight*rate);
      repriced.push({name,qty,weight,rate,amount});subtotal+=amount;
    }
    if(identity.role==='staff' && Math.abs(inv.discount)>0.005)throw new Error('Only Admin may apply discounts');
    if(!Number.isFinite(inv.discount)||inv.discount<0||inv.discount>subtotal)throw new Error('Invalid invoice discount');
    inv.items=repriced;inv.subTotal=subtotal;inv.grandTotal=Math.max(0,subtotal-inv.discount);
    if(inv.paymentType==='cash')inv.amountPaid=inv.grandTotal;
    if(!Number.isFinite(inv.amountPaid)||inv.amountPaid<0||inv.amountPaid>inv.grandTotal+0.005)throw new Error('Invalid payment amount');
    inv.balance=Math.round((inv.grandTotal-inv.amountPaid)*100)/100;
    return;
  }
  if(!priceList.enforced)return; // Setup Mode retains legacy rates only for active catalog products.
  const catalog=new Map(priceList.products.map(p=>[p.name,p]));
  if(!Array.isArray(inv.items)||!inv.items.length||inv.items.length>150)throw new Error('Add valid products from the Price List');
  let subtotal=0;
  const repriced=[];
  for(const x of inv.items){
    const name=String(x.name||'').trim(),p=catalog.get(name);
    if(!p)throw new Error('Product '+name+' is not in the approved Price List');
    if(p.rate===null)throw new Error('Admin has not set a price for '+name+'. Invoice not saved.');
    const qty=Number(x.qty);
    if(!Number.isFinite(qty)||qty<=0||qty>100000||Math.round(qty*1000)!==qty*1000)throw new Error('Invalid quantity for '+name);
    // Both fixed and factor-priced products use actual KG entered by Staff.
    // The price per KG always comes from the approved catalog, never the browser.
    // Check raw input strictly: null, absent, or blank weight cannot become zero.
    const rawWeight=x.weight;
    if(rawWeight===null||rawWeight===undefined||rawWeight==='')throw new Error('Enter actual weight for '+name);
    const weight=Number(rawWeight);
    if(!Number.isFinite(weight)||weight<=0||weight>100000)throw new Error('Enter a valid positive weight for '+name);
    if(Math.abs(weight-Math.round(weight*1000)/1000)>0.000001)throw new Error('Weight supports up to three decimal places for '+name);
    const amount=Math.round(weight*p.rate);
    repriced.push({name,qty,weight,rate:p.rate,amount});subtotal+=amount;
  }
  // Staff cannot use discounts to bypass the approved price list.
  if(identity.role==='staff' && Math.abs(inv.discount)>0.005)throw new Error('Only Admin may apply discounts');
  if(!Number.isFinite(inv.discount)||inv.discount<0||inv.discount>subtotal)throw new Error('Invalid invoice discount');
  inv.items=repriced;inv.subTotal=subtotal;inv.grandTotal=Math.max(0,subtotal-inv.discount);
  if(inv.paymentType==='cash')inv.amountPaid=inv.grandTotal;
  if(inv.amountPaid<0||inv.amountPaid>inv.grandTotal+0.005)throw new Error('Payment amount is invalid for approved prices');
  inv.balance=Math.round((inv.grandTotal-inv.amountPaid)*100)/100;
}


/* ---------- Unified product catalog: soft archive, never re-index historical stock/orders ---------- */
const SC_TRACKED_CATEGORIES = new Set(['Main Products','By Parts Products','Marinated Products','Further Products','Inventory Products']);
const SC_PRODUCT_CATEGORIES=['Main Products','By Parts Products','Marinated Products','Further Products','Youngs & National','Grocery'];
function scProductDTO(r){return {name:r.product_name,category:r.category,packKg:Number(r.kg_per_packet),active:r.is_active,stockIndex:r.stock_index,orderIndex:r.order_index};}
app.get('/api/products/catalog',auth,async(req,res)=>{
 if(!readRoleIdentity(req))return res.status(403).json({error:'POS login required'});
 try{const r=await pool.query('select product_name,category,kg_per_packet,is_active,stock_index,order_index from public.sc_product_catalog order by created_at,product_name');res.set('Cache-Control','no-store');res.json({products:r.rows.map(scProductDTO),categories:SC_PRODUCT_CATEGORIES});}
 catch(e){console.error('Unified product catalog read failed',e);res.status(503).json({error:'Unified catalog not installed. Run unified_products.sql in Supabase.'});}
});
app.post('/api/products',auth,adminOnly,async(req,res)=>{
 const name=String(req.body?.name||'').replace(/\s+/g,' ').trim();
 const category=String(req.body?.category||'');
 const packKg=Number(req.body?.packKg);
 if(name.length<2||name.length>120||!SC_PRODUCT_CATEGORIES.includes(category)||!Number.isFinite(packKg)||packKg<=0||packKg>100)return res.status(400).json({error:'Enter a valid product name, category and kg/packet'});
 const type=category==='Marinated Products'?'factor':'fixed';
 const tracked=SC_TRACKED_CATEGORIES.has(category);
 const db=await pool.connect();
 try{
  await db.query('begin');
  await db.query("select pg_advisory_xact_lock(hashtext('sc-products-add'))");
  const exists=await db.query('select 1 from public.sc_product_catalog where lower(trim(product_name))=lower($1)',[name]);
  if(exists.rowCount){await db.query('rollback');return res.status(409).json({error:'Product already exists (possibly archived). Use Restore for archived products.'});}
  let stockIndex=null,orderIndex=null;
  if(tracked){
   const mx=await db.query('select coalesce(max(stock_index),$1)::integer+1 as s,coalesce(max(order_index),$2)::integer+1 as o from public.sc_product_catalog',[SC_STOCK_BASE_LENGTH-1,SC_ORDER_ITEMS.length-1]);
   stockIndex=Math.max(SC_STOCK_BASE_LENGTH,Number(mx.rows[0].s));
   orderIndex=Math.max(SC_ORDER_ITEMS.length,Number(mx.rows[0].o));
  }
  const row=await db.query('insert into public.sc_product_catalog(product_name,category,kg_per_packet,stock_index,order_index,changed_by) values($1,$2,$3,$4,$5,$6) returning *',[name,category,packKg,stockIndex,orderIndex,auditIdentity(req).id]);
  await db.query('insert into public.sc_price_products(product_name,pricing_type,kg_per_packet) values($1,$2,$3)',[name,type,packKg]);
  await writeAudit(db,req,'product.created',null,null,{product:name,category,packKg,stockIndex,orderIndex});
  await db.query('commit');scNotifyPriceChanged();res.status(201).json(scProductDTO(row.rows[0]));
 }catch(e){await db.query('rollback').catch(()=>{});console.error('Product add failed',e);res.status(503).json({error:'Could not add product; no changes saved.'});}
 finally{db.release();}
});
app.put('/api/products/archive',auth,adminOnly,async(req,res)=>{
 const name=String(req.body?.name||'');const active=req.body?.active;
 if(!name||typeof active!=='boolean')return res.status(400).json({error:'Choose product and archive/restore action'});
 const db=await pool.connect();try{
  await db.query('begin');
  const result=await db.query('update public.sc_product_catalog set is_active=$2,changed_at=now(),changed_by=$3 where product_name=$1 returning *',[name,active,auditIdentity(req).id]);
  if(!result.rowCount){await db.query('rollback');return res.status(404).json({error:'Product not found'});}
  await writeAudit(db,req,active?'product.restored':'product.archived',null,null,{product:name,stockIndex:result.rows[0].stock_index,orderIndex:result.rows[0].order_index});
  await db.query('commit');scNotifyPriceChanged();res.json(scProductDTO(result.rows[0]));
 }catch(e){await db.query('rollback').catch(()=>{});console.error('Product archive failed',e);res.status(503).json({error:'Product update failed'});}finally{db.release();}
});
// Order+stock legacy arrays retain their original indexes. New tracked items append ONLY.
const SC_STOCK_BASE_LENGTH = 90;
async function scOrderCurrentCatalog(db){
 const r=await db.query('select product_name,kg_per_packet,is_active,order_index from public.sc_product_catalog where order_index is not null order by order_index');
 const items=SC_ORDER_ITEMS.map(x=>x.slice());const active=[];
 for(const p of r.rows){const index=Number(p.order_index);if(index>=items.length)while(items.length<=index)items.push(null);
  items[index]=[p.product_name,Number(p.kg_per_packet)];if(p.is_active)active.push(index);}
 return {items,active};
}

/* ---------- Shop orders: read-only inventory reconciliation (never changes stock) ---------- */
const SC_ORDER_BRANCHES=['Hatchery','Kasur','Gajjumatta','Mustafabad','Gulshan Ravi','Murghzar'];
const SC_ORDER_ITEMS=[["SBB Trimming",2],["SBB Slice",2],["Skinless Breast",1],["Boneless Handi",1],["Boneless Breast",2],["Breast RS",2],["Breast Yum",2],["Premium Mince",1],["Zinger CP S/O",2],["Zinger CP S/L",2],["Zinger S/L JC/RS",2],["Drumstick S/O",1],["Drumstick S/L",1],["Karahi Cut",1],["2 Pcs Cut/Combo Cut",1],["Whole Bird S/O",1],["Whole Bird S/L",1],["Inner Fillet",2],["Thigh Trimming",2],["Trimming Bone",2],["Whole Leg",2],["Drummet A",2],["Drummet B",2],["Niblet A",2],["Niblet B",2],["Wing Tip",2],["3 Joint Wings",2],["2 Joint Wings S/O",2],["2 Joint Wings S/L",1],["D Trimming",2],["Neck",1],["Carcass",4],["Skin",2],["Tail",2],["Heart",1],["Liver",1],["Gizzard",1],["Shanks",1],["MDM Mince",1],["Marinated ButterFly JC",2],["Marinated ButterFly LC",2],["Marinated Niblet 1kg",1],["Marinated Niblet",2],["Marinated Drummet 1kg",1],["Marinated Drummet",2],["Marinated 5 cut",2],["Injected Chicken Pieces",3.5],["Marinated Zinger CP",2],["Marinated Zinger SBL",2],["Marinated Zinger S/O",2],["Marinated Zinger S/L",2],["Marinated Drumstick",1],["Marinated Strips",1],["Marinated Strips 2kg",2],["Marinated Crispy",1],["Kebab",0.5],["Nuggets",1],["Chicken Fries",1],["Burger Patty 12 Pcs",0.96],["Burger Patty 8 Pcs",0.48],["Chicken Samosa 12 pcs",0.3],["Chicken Samosa 24 pcs",0.6],["Fried Samosa",0.5],["Fried Spring Roll",0.5],["Chicken Roll 12 pcs",0.42],["Chicken Roll 24 pcs",0.84],["Breading Flour",1],["Chapli Kabab",0.5],["Chicken Kofta",1],["Pizza Topping Tikka",1],["Pizza Topping Fajita",1],["Boneless Breast (110-140)",2],["Zinger Skinless 70-100",2],["Marinated Thigh",2],["Fajita Topping",0.5],["Innerfillet",2],["Boneless Breast RS (120-130)",2],["3 Joined Wings",2],["2 Pc Cut",1],["Breading flour",3],["Tikka Topping",0.5],["Malai Boti Topping",0.5],["Liver & Heart",1],["Marinated Butterfly",2],["Marinade Injected Chicken Pieces",3],["D-Triming",2],["Marinated SBB Crispy",1.5],["Skinless Breast Star Chicken",1],["Extra",1],["Shanks (kg)",1],["SBB Triming/B Grade Trimming",2],["Quarter Cut/4 cut",1]];
const scOrderMoney=n=>Math.round(Number(n||0)*100)/100;
const scOrderDateValid=s=>typeof s==='string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s+'T00:00:00Z')) && new Date(s+'T00:00:00Z').toISOString().slice(0,10)===s;
function scOrderPublic(row){const dt=x=>x instanceof Date?x.toISOString().slice(0,10):String(x).slice(0,10);return {id:row.id,orderNo:row.order_no,branch:row.branch,orderDate:dt(row.order_date),expectedDate:dt(row.expected_date),deliveryDate:row.delivery_date?dt(row.delivery_date):null,status:row.status,items:row.items,receipts:row.receipts||[],notes:row.notes||'',createdBy:row.created_by,completedBy:row.completed_by||'',createdAt:row.created_at,completedAt:row.completed_at};}
app.get('/api/shop-orders/catalog',auth,async(req,res)=>{if(!readRoleIdentity(req))return res.status(403).json({error:'POS Staff or Admin login required'});try{const catalog=await scOrderCurrentCatalog(pool);res.json({branches:SC_ORDER_BRANCHES,...catalog});}catch(e){console.error(e);res.status(503).json({error:'Cannot load product catalog'});}});
app.get('/api/shop-orders',auth,async(req,res)=>{
  if(!readRoleIdentity(req))return res.status(403).json({error:'POS Staff or Admin login required'});
  try{const rows=await scShopOrdersCache.get(async()=>{const r=await pool.query('select * from public.sc_shop_orders order by created_at desc limit 2000');return r.rows.map(scOrderPublic);});res.set('Cache-Control','no-store');res.json(rows);}
  catch(e){console.error('Shop order listing failed',e);res.status(503).json({error:'Order tables unavailable. Run shop_orders.sql first.'});}
});
app.post('/api/shop-orders',auth,async(req,res)=>{
  if(!readRoleIdentity(req))return res.status(403).json({error:'POS Staff or Admin login required'});
  const x=req.body||{},branch=String(x.branch||''),day=String(x.orderDate||''),expected=String(x.expectedDate||''),notes=String(x.notes||'').trim();
  if(!SC_ORDER_BRANCHES.includes(branch)||!scOrderDateValid(day)||!scOrderDateValid(expected)||notes.length>400)return res.status(400).json({error:'Choose a valid branch and dates'});
  const input=Array.isArray(x.items)?x.items:[];
  const liveOrderCatalog=await scOrderCurrentCatalog(pool);if(!input.length||input.length>liveOrderCatalog.active.length)return res.status(400).json({error:'Add products to the order'});
  const used=new Set(),clean=[];
  for(const it of input){const i=Number(it.index),q=Number(it.qty);if(!Number.isInteger(i)||i<0||!liveOrderCatalog.active.includes(i)||used.has(i)||!Number.isFinite(q)||q<=0||q>100000||Math.round(q*1000)!==q*1000)return res.status(400).json({error:'Invalid product or packet quantity'});used.add(i);clean.push({index:i,name:liveOrderCatalog.items[i][0],kgPerPacket:liveOrderCatalog.items[i][1],qty:q});}
  const by=auditIdentity(req).id;
  const client=await pool.connect();
  try{await client.query('begin');const counter=await client.query("select nextval('public.sc_shop_order_numbers') as n");const number='ORD-'+String(counter.rows[0].n).padStart(6,'0');
    const inserted=await client.query('insert into public.sc_shop_orders(order_no,branch,order_date,expected_date,items,notes,created_by) values($1,$2,$3,$4,$5::jsonb,$6,$7) returning *',[number,branch,day,expected,JSON.stringify(clean),notes,by]);
    await writeAudit(client,req,'shop.order.created',null,number,{branch,items:clean.length});await client.query('commit');scShopOrdersCache.invalidate();res.status(201).json(scOrderPublic(inserted.rows[0]));
  }catch(e){await client.query('rollback').catch(()=>{});console.error('Order create failed',e);res.status(503).json({error:'Could not save order to Supabase'});}finally{client.release();}
});
/* Admin-only order cleanup. Stock sheets and invoice records are NEVER changed. */
app.delete('/api/shop-orders/:id',auth,adminOnly,async(req,res)=>{
  const id=String(req.params.id||'');
  const confirmation=String(req.body?.confirmOrderNo||'').trim();
  const reason=String(req.body?.reason||'').trim();
  if(!/^[0-9a-f-]{36}$/i.test(id))return res.status(400).json({error:'Invalid order ID'});
  if(reason.length<8||reason.length>300)return res.status(400).json({error:'Enter a reason of at least 8 characters'});
  const client=await pool.connect();
  try{
    await client.query('begin');
    const result=await client.query('select * from public.sc_shop_orders where id=$1 for update',[id]);
    if(!result.rowCount){await client.query('rollback');return res.status(404).json({error:'Order not found. Refresh Orders.'});}
    const order=result.rows[0];
    if(confirmation!==order.order_no){await client.query('rollback');return res.status(400).json({error:'Confirmation must exactly match the order number'});}
    // An audit snapshot protects traceability of the removed order and its allocation.
    await writeAudit(client,req,'shop.order.admin_deleted',null,order.order_no,{
      reason,branch:order.branch,orderDate:order.order_date,
      deliveryDate:order.delivery_date,status:order.status,
      items:order.items,receipts:order.receipts,
      createdBy:order.created_by,completedBy:order.completed_by,
      stockUnchanged:true
    });
    await client.query('delete from public.sc_shop_orders where id=$1',[id]);
    await client.query('commit');
    scShopOrdersCache.invalidate();
    res.json({ok:true,orderNo:order.order_no,stockUnchanged:true});
  }catch(e){try{await client.query('rollback')}catch(_){}console.error('Admin order deletion failed',e);res.status(503).json({error:'Order not deleted. Check Activity Log and server logs.'});}
  finally{client.release();}
});

// Preview reads the SAME daily receipt columns in Inventory Management; it never changes stock.
async function scOrderPreview(db,order,deliveryDate){
  const stock=await db.query('select state from public.stock_app_state where id=1');
  const state=stock.rows[0]?.state||{},daily=state.stockDB?.[order.branch]?.[deliveryDate];
  if(!daily||!Array.isArray(daily.r))return {available:false,error:'There is no SAVED Inventory Management stock sheet for this branch and delivery date. Save Received quantities in Inventory first.'};
  const consumed=await db.query("select receipts from public.sc_shop_orders where branch=$1 and status='completed' and delivery_date=$2 and id<>$3",[order.branch,deliveryDate,order.id]);
  const byItem=new Map();for(const row of consumed.rows)for(const rec of(row.receipts||[])){const k=Number(rec.index);byItem.set(k,scOrderMoney((byItem.get(k)||0)+Number(rec.qty||0)));}
  const summary=[];
  for(const item of order.items){const i=item.index,qty=Number(item.qty),available=scOrderMoney(Math.max(0,Number(daily.r[i]?.[1]||0)-(byItem.get(i)||0)));
    // A dated stock sheet may contain receipts from unrelated orders; allocation is selected by shopman.
    summary.push({index:i,name:item.name,ordered:qty,receivedAvailable:available,kgPerPacket:item.kgPerPacket});}
  return {available:true,products:summary,deliveryDate,branch:order.branch};
}
app.get('/api/shop-orders/:id/receipt-preview',auth,async(req,res)=>{
  if(!readRoleIdentity(req))return res.status(403).json({error:'POS Staff or Admin login required'});
  const day=String(req.query.deliveryDate||'');if(!scOrderDateValid(day))return res.status(400).json({error:'Invalid delivery date'});
  try{const r=await pool.query('select * from public.sc_shop_orders where id=$1',[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Order not found'});if(r.rows[0].status!=='open')return res.status(409).json({error:'Order already completed'});res.json(await scOrderPreview(pool,r.rows[0],day));}
  catch(e){console.error('Receipt preview failed',e);res.status(503).json({error:'Could not load saved stock receipts'});}
});
app.post('/api/shop-orders/:id/complete',auth,async(req,res)=>{
  if(!readRoleIdentity(req))return res.status(403).json({error:'POS Staff or Admin login required'});
  const deliveryDate=String(req.body?.deliveryDate||'');if(!scOrderDateValid(deliveryDate))return res.status(400).json({error:'Enter valid delivery date'});
  const selected=Array.isArray(req.body?.received)?req.body.received:null;
  if(!selected)return res.status(400).json({error:'Enter received quantities'});
  const client=await pool.connect();
  try{await client.query('begin');const r=await client.query('select * from public.sc_shop_orders where id=$1 for update',[req.params.id]);
    if(!r.rowCount){await client.query('rollback');return res.status(404).json({error:'Order not found'});}
    const order=r.rows[0];if(order.status!=='open'){await client.query('rollback');return res.status(409).json({error:'This order has already been completed'});}
    // Serializes stock allocation by branch+delivery date across different orders.
    await client.query('select pg_advisory_xact_lock(hashtext($1))',[`sc-order:${order.branch}:${deliveryDate}`]);
    const preview=await scOrderPreview(client,order,deliveryDate);if(!preview.available){await client.query('rollback');return res.status(409).json({error:preview.error});}
    const requested=new Map();for(const x of selected){const i=Number(x.index),qty=Number(x.qty);if(!Number.isInteger(i)||requested.has(i)||!Number.isFinite(qty)||qty<0||qty>100000||Math.round(qty*1000)!==qty*1000){await client.query('rollback');return res.status(400).json({error:'Invalid received quantities'});}requested.set(i,qty);}
    if(requested.size!==order.items.length||order.items.some(it=>!requested.has(it.index))){await client.query('rollback');return res.status(400).json({error:'Submit all order products, including zero received quantities'});}
    const receipts=[];for(const p of preview.products){const qty=requested.get(p.index);if(qty>p.receivedAvailable+0.0001){await client.query('rollback');return res.status(409).json({error:p.name+': received quantity exceeds available unallocated stock-sheet receipts. Refresh and check Inventory Management.'});}receipts.push({index:p.index,qty,deliveryDate});}
    const completedBy=auditIdentity(req).id;
    const changed=await client.query("update public.sc_shop_orders set status='completed',delivery_date=$2,receipts=$3::jsonb,completed_at=now(),completed_by=$4 where id=$1 returning *",[order.id,deliveryDate,JSON.stringify(receipts),completedBy]);
    await writeAudit(client,req,'shop.order.completed',null,order.order_no,{branch:order.branch,deliveryDate,receipts});await client.query('commit');scShopOrdersCache.invalidate();res.json(scOrderPublic(changed.rows[0]));
  }catch(e){await client.query('rollback').catch(()=>{});console.error('Completing order failed',e);res.status(503).json({error:'Could not complete order. No changes saved.'});}finally{client.release();}
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


/* ---------- Shared in-process query cache (Supabase egress reduction) ----------
   This caches READ responses on Render, not in Supabase or in a staff browser.
   A concurrent burst shares one PostgreSQL query. Successful writes invalidate
   immediately. Failed DB reads are NEVER cached. No cross-instance cache is used.
*/
function scReadCache(ttlMs) {
  let value, expiresAt=0, inFlight=null, generation=0;
  return {
    async get(loader) {
      if (value !== undefined && Date.now() < expiresAt) return value;
      if (inFlight && inFlight.generation === generation) return inFlight.promise;
      const observed = generation;
      const promise = (async () => {
        const loaded = await loader();
        if (generation === observed) { value=loaded; expiresAt=Date.now()+ttlMs; }
        return loaded;
      })();
      inFlight={promise,generation:observed};
      try { return await promise; }
      finally { if (inFlight?.promise === promise) inFlight=null; }
    },
    invalidate() { generation++; value=undefined; expiresAt=0; inFlight=null; }
  };
}
// The full invoice query is deliberately unchanged: Dashboard, reports, stock
// and old invoice screens all require the complete (including items) dataset.
const scInvoiceListCache=scReadCache(3*60*1000);
const scStockStateCache=scReadCache(30*1000);
const scShopOrdersCache=scReadCache(60*1000);

/* ---------- Shared stock / POS inventory state ---------- */
app.get('/api/stock/state', auth, async (req, res) => {
  try { const result=await scStockStateCache.get(async()=>{const r=await pool.query('select state, updated_at from public.stock_app_state where id=1');return {state:r.rowCount?r.rows[0].state:null,updatedAt:r.rowCount?r.rows[0].updated_at:null};});res.set('Cache-Control','no-store');res.json(result); }
  catch(e){ console.error('Could not load stock state:',e); res.status(500).json({error:'Could not load stock data. Run schema_additions.sql in Supabase SQL Editor.'}); }
});
/* Stock permissions: Karachi business day; past stock receiving and opening are Admin-only.
   POS invoice synchronization can still update derived Sale values in older sheets. */
const scStockToday = () => new Intl.DateTimeFormat('sv-SE', {timeZone:'Asia/Karachi',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());
const scStockNumeric = x => { const v=Number(x); return Number.isFinite(v)?v:0; };
const scStockBal = a => scStockNumeric(a?.[0])+scStockNumeric(a?.[1])-scStockNumeric(a?.[2])-scStockNumeric(a?.[3]);
const scStockRound = x => Math.round(x*1000)/1000;
const scStockCanonical = x => JSON.stringify(x??null);
function scStockProtectedChanges(oldDb={},newDb={},today=scStockToday()) {
  const branches=new Set([...Object.keys(oldDb||{}),...Object.keys(newDb||{})]);
  for (const branch of branches) {
    const oldDays=oldDb?.[branch]||{},newDays=newDb?.[branch]||{};
    const days=new Set([...Object.keys(oldDays),...Object.keys(newDays)]);
    for (const day of days) {
      if(day===today)continue;
      const before=oldDays[day],after=newDays[day];
      if(!before&&!after)continue;
      if(!before||!after)return `${branch}, ${day}: only today's stock sheet can be changed by Staff`;
      // Existing historical sheets may receive refreshed invoice-derived Sale quantities (index 2).
      // Never accept historical opening, received, transfer or arbitrary metadata changes from Staff.
      const oldRows=before.r||[],newRows=after.r||[];
      const len=Math.max(oldRows.length,newRows.length);
      for(let i=0;i<len;i++){
        const a=oldRows[i]||['','','',''],b=newRows[i]||['','','',''];
        for(const c of [0,1,3])if(scStockCanonical(a[c]??'')!==scStockCanonical(b[c]??'')){
          // An absent appended row and an explicit empty row are equivalent.
          if(scStockNumeric(a[c])===0&&scStockNumeric(b[c])===0)continue;
          return `${branch}, ${day}: historical Opening/Received/Return changes require Admin`;
        }
      }
      const restA={...before};delete restA.r;
      const restB={...after};delete restB.r;
      if(scStockCanonical(restA)!==scStockCanonical(restB))return `${branch}, ${day}: historical sheet changes require Admin`;
    }
  }
  return null;
}
function scStockOpeningProposal(state,branch,day){
  if(!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(day)||!branch||branch.length>100)throw new Error('Choose a valid branch and date');
  const db=state.stockDB||{},days=db[branch]||{},target=days[day];
  if(!target||!Array.isArray(target.r))throw new Error('Save this date’s stock sheet first, then recalculate its opening');
  const prior=Object.keys(days).filter(d=>d<day&&Array.isArray(days[d]?.r)).sort().at(-1);
  if(!prior)throw new Error('No earlier saved stock sheet exists for this branch');
  const previous=days[prior].r||[],current=target.r||[],sales=state.posSales?.[branch]?.[prior];
  const changes=[];
  const len=Math.max(previous.length,current.length);
  for(let i=0;i<len;i++){
    const source=previous[i]||['','','',''];
    const sold=Array.isArray(sales)?scStockNumeric(sales[i]):scStockNumeric(source[2]);
    const proposed=scStockRound(scStockNumeric(source[0])+scStockNumeric(source[1])-sold-scStockNumeric(source[3]));
    const existing=current[i]?.[0];
    if(Math.abs(proposed-scStockNumeric(existing))>0.000001 || (existing===''||existing==null)&&proposed===0){
      changes.push({index:i,old:existing??'',next:proposed,previousReceived:scStockNumeric(source[1]),previousSold:sold});
    }
  }
  const basis=crypto.createHash('sha256').update(JSON.stringify({branch,day,prior,previous,current,sales:sales||null})).digest('hex');
  return {branch,date:day,previousDate:prior,changes,basis};
}
/* This targeted endpoint updates ONLY opening cells of the selected saved day.
   It does not touch receipts, transfers, invoice-derived sales, or other dates. */
app.get('/api/stock/recalculate-opening',auth,adminOnly,async(req,res)=>{
  try{
    const r=await pool.query('select state from public.stock_app_state where id=1');
    if(!r.rowCount)return res.status(404).json({error:'No saved Inventory state found'});
    res.set('Cache-Control','no-store');res.json(scStockOpeningProposal(r.rows[0].state||{},String(req.query.branch||''),String(req.query.date||'')));
  }catch(e){res.status(400).json({error:e.message||'Could not preview opening'});}
});
app.post('/api/stock/recalculate-opening',auth,adminOnly,async(req,res)=>{
  const db=await pool.connect();
  try{
    await db.query('begin');
    const r=await db.query('select state from public.stock_app_state where id=1 for update');
    if(!r.rowCount)throw new Error('No saved Inventory state found');
    const state=r.rows[0].state||{};
    const preview=scStockOpeningProposal(state,String(req.body?.branch||''),String(req.body?.date||''));
    if(!req.body?.basis||req.body.basis!==preview.basis){await db.query('rollback');return res.status(409).json({error:'Stock changed since preview. Please preview again before confirming.'});}
    if(!preview.changes.length){await db.query('rollback');return res.json({ok:true,changed:0});}
    const rows=state.stockDB[preview.branch][preview.date].r;
    for(const item of preview.changes){
      while(rows.length<=item.index)rows.push(['','','','']);
      if(!Array.isArray(rows[item.index]))rows[item.index]=['','','',''];
      rows[item.index][0]=item.next;
    }
    await db.query('update public.stock_app_state set state=$1::jsonb,updated_at=now() where id=1',[JSON.stringify(state)]);
    await writeAudit(db,req,'stock.opening.recalculated',null,null,{branch:preview.branch,date:preview.date,previousDate:preview.previousDate,changes:preview.changes});
    await db.query('commit');scStockStateCache.invalidate();res.json({ok:true,changed:preview.changes.length});
  }catch(e){await db.query('rollback').catch(()=>{});console.error('Stock opening recalculation error',e);res.status(500).json({error:e.message||'Opening not changed'});}finally{db.release();}
});

app.put('/api/stock/state', auth, async (req, res) => {
  const state=req.body?.state;
  if(!state||typeof state!=='object'||Array.isArray(state)) return res.status(400).json({error:'A valid stock state object is required'});
  if(JSON.stringify(state).length>1_800_000) return res.status(413).json({error:'Stock data is too large to save'});
  const identity=readRoleIdentity(req);
  if(!identity)return res.status(403).json({error:'POS Staff or Admin login required for stock changes'});
  const client=await pool.connect();
  try{
    await client.query('begin');
    const old=await client.query('select state from public.stock_app_state where id=1 for update');
    if(identity.role!=='admin'){
      const invalid=scStockProtectedChanges(old.rows[0]?.state?.stockDB||{},state.stockDB||{});
      if(invalid){await client.query('rollback');return res.status(403).json({error:invalid});}
    }
    const r=await client.query(`insert into public.stock_app_state(id,state,updated_at) values(1,$1::jsonb,now()) on conflict(id) do update set state=excluded.state,updated_at=now() returning updated_at`,[JSON.stringify(state)]);
    await client.query('commit');scStockStateCache.invalidate();res.json({ok:true,updatedAt:r.rows[0].updated_at});
  }catch(e){await client.query('rollback').catch(()=>{});console.error('Could not save stock state:',e);res.status(500).json({error:'Could not save stock data. Verify the cloud state connection.'});}
  finally{client.release();}
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
    const a=await pool.query(`select c.invoice_id,c.invoice_no,c.customer_name,c.grand_total,c.amount_paid,
      c.outstanding_at_sale,c.prepared_by,c.created_at,v.voided_at,v.voided_by,v.reason as void_reason
      from public.sc_credit_invoices c
      left join public.sc_credit_voids v on v.invoice_id=c.invoice_id
      order by c.created_at desc`);
    const b=await pool.query(`select id,customer_name,amount,method,note,received_by,created_at
      from public.sc_credit_payments order by created_at desc`);
    const accounts=new Map();
    function get(name){const key=String(name).trim().toLowerCase();if(!accounts.has(key))accounts.set(key,{customerName:name,creditSales:0,received:0,outstanding:0});return accounts.get(key)}
    for(const r of a.rows){let x=get(r.customer_name);if(r.voided_at)continue;x.creditSales+=Number(r.grand_total);x.received+=Number(r.amount_paid);x.outstanding+=Number(r.outstanding_at_sale)}
    for(const r of b.rows){let x=get(r.customer_name);x.received+=Number(r.amount);x.outstanding-=Number(r.amount)}
    const round=n=>Math.round(n*100)/100;
    res.setHeader('Cache-Control','no-store');
    res.json({accounts:[...accounts.values()].map(a=>({...a,creditSales:round(a.creditSales),received:round(a.received),outstanding:round(a.outstanding)})).sort((a,b)=>a.customerName.localeCompare(b.customerName)),
      invoices:a.rows.map(r=>({invoiceId:r.invoice_id,invoiceNo:r.invoice_no,customerName:r.customer_name,grandTotal:Number(r.grand_total),amountPaid:Number(r.amount_paid),outstandingAtSale:Number(r.outstanding_at_sale),preparedBy:r.prepared_by,createdAt:Date.parse(r.created_at),voided:!!r.voided_at,voidedAt:r.voided_at?Date.parse(r.voided_at):null,voidedBy:r.voided_by||'',voidReason:r.void_reason||''})),
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
      from public.sc_credit_invoices c where lower(trim(c.customer_name))=lower($1)
      and not exists(select 1 from public.sc_credit_voids v where v.invoice_id=c.invoice_id)`,[name]);
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

/* ---------- Admin-only, audited credit invoice void ----------
   The original invoice + credit record remain unchanged for audit. A separate
   void marker excludes it from active sales/stock and credit totals. Later
   customer-level payments are never erased or silently reallocated.
*/
app.post('/api/credit/invoices/:id/void',auth,adminOnly,async(req,res)=>{
  const id=String(req.params.id||'');
  const reason=String(req.body?.reason||'').trim();
  if(!id||id.length>150||reason.length<5||reason.length>300)
    return res.status(400).json({error:'Enter a reason (5 to 300 characters) for voiding this invoice.'});
  const client=await pool.connect();
  try{
    await client.query('begin');
    const found=await client.query('select invoice_id,invoice_no,customer_name,outstanding_at_sale from public.sc_credit_invoices where invoice_id=$1',[id]);
    if(!found.rowCount){await client.query('rollback');return res.status(404).json({error:'This is not a new credit invoice.'});}
    const customer=found.rows[0].customer_name;
    await client.query('select pg_advisory_xact_lock(hashtext(lower($1)))',[customer]);
    const already=await client.query('select 1 from public.sc_credit_voids where invoice_id=$1',[id]);
    if(already.rowCount){await client.query('rollback');return res.status(409).json({error:'This invoice has already been voided.'});}
    // Serialized with payment collection for the same customer.
    const active=await client.query(`select coalesce(sum(c.outstanding_at_sale),0)::numeric as due
      from public.sc_credit_invoices c
      where lower(trim(c.customer_name))=lower(trim($1))
      and not exists(select 1 from public.sc_credit_voids v where v.invoice_id=c.invoice_id)`,[customer]);
    const paid=await client.query(`select coalesce(sum(amount),0)::numeric as paid
      from public.sc_credit_payments where lower(trim(customer_name))=lower(trim($1))`,[customer]);
    const balance=Math.round((Number(active.rows[0].due)-Number(paid.rows[0].paid))*100)/100;
    const remove=Number(found.rows[0].outstanding_at_sale);
    if(balance+0.005<remove){await client.query('rollback');return res.status(409).json({error:'Cannot void: this customer already has later payments covering part of the invoice. Payments cannot be reassigned automatically. Contact Admin to reconcile refunds or allocations first.'});}
    const by=readRoleIdentity(req)?.staffId||'Admin';
    await client.query(`insert into public.sc_credit_voids(invoice_id,reason,voided_by) values($1,$2,$3)`,[id,reason,by]);
    await writeAudit(client,req,'credit.invoice.voided',id,found.rows[0].invoice_no,{customerName:customer,reason,outstandingReversed:remove});
    await client.query('commit');
    scPublishInvoiceChange('voided',found.rows[0].invoice_no);
    res.json({ok:true,invoiceNo:found.rows[0].invoice_no,customerName:customer,outstandingReversed:remove,newCustomerBalance:Math.round((balance-remove)*100)/100});
  }catch(e){try{await client.query('rollback')}catch(_){}console.error('Credit invoice void failed',e);res.status(503).json({error:'Could not void the invoice. Confirm credit_voids.sql was installed.'});}
  finally{client.release();}
});


/* ---------- One-time Admin cleanup for TWO explicitly identified test invoices ----------
   No changes happen on deployment or preview. This route is deliberately restricted
   to SC-PC-2400 and SC-PC-2402, their exact customer names, original amounts,
   and exact later-payment patterns observed in the test screenshots.
   Cleaned records disappear from active POS and credit ledger; invoice counter is
   never changed and the cleanup is recorded in the existing Admin activity log.
   REMOVE THIS ENTIRE BLOCK after the one-time cleanup is finished.
*/
const approvedTestCreditCleanup = Object.freeze({
  'SC-PC-2400': Object.freeze({customer:'K & K Biryani and Fast Food', total:6000, atSale:0, later:[6000]}),
  'SC-PC-2402': Object.freeze({customer:'Liaqat Ali', total:5000, atSale:1000, later:[2000,2000]})
});
const testCreditMoney = v => Math.round(Number(v)*100);
async function inspectApprovedTestCredit(client, invoiceNo) {
  const spec=approvedTestCreditCleanup[invoiceNo];
  if(!spec)return {safe:false,reason:'This invoice is not on the two-invoice cleanup allowlist.'};
  // The same advisory lock used for credit-payment collection protects the
  // customer against simultaneous payment/void requests during cleanup.
  await client.query('select pg_advisory_xact_lock(hashtext(lower($1)))',[spec.customer]);
  const invoices=await client.query(`select i.id,i.invoice_no,i.invoice_date,i.customer_name,i.shop_name,
      i.grand_total,i.amount_paid,c.invoice_id,c.invoice_no as credit_no,
      c.customer_name as credit_customer,c.grand_total as credit_total,
      c.amount_paid as credit_paid,c.outstanding_at_sale
    from public.invoices i join public.sc_credit_invoices c on c.invoice_id=i.id
    where i.invoice_no=$1 for update of i,c`,[invoiceNo]);
  if(invoices.rowCount!==1)return {safe:false,reason:'Matching original POS invoice and credit entry were not both found.'};
  const r=invoices.rows[0];
  const exact=(a,b)=>String(a).trim()===b;
  if(!exact(r.invoice_no,invoiceNo)||!exact(r.credit_no,invoiceNo)||
     !exact(r.credit_customer,spec.customer)||!exact(r.shop_name,spec.customer)||
     testCreditMoney(r.grand_total)!==testCreditMoney(spec.total)||
     testCreditMoney(r.credit_total)!==testCreditMoney(spec.total)||
     testCreditMoney(r.amount_paid)!==testCreditMoney(spec.atSale)||
     testCreditMoney(r.credit_paid)!==testCreditMoney(spec.atSale)||
     testCreditMoney(r.outstanding_at_sale)!==testCreditMoney(spec.total-spec.atSale))
    return {safe:false,reason:'Invoice or credit amounts/customer differ from the approved test data.'};
  // The screenshots show these invoices created on 14 November 2026. This
  // extra condition prevents an accidental match to a different invoice.
  const date= r.invoice_date instanceof Date ? r.invoice_date.toISOString().slice(0,10):String(r.invoice_date).slice(0,10);
  if(date!=='2026-11-14')return {safe:false,reason:'Invoice date is not the expected test date.'};
  // Prevent deletion when any other real credit invoice uses this customer's
  // name, since later payments are stored at customer-account level.
  const other=await client.query(`select count(*)::int as count from public.sc_credit_invoices
    where lower(trim(customer_name))=lower(trim($1)) and invoice_id<>$2`,[spec.customer,r.id]);
  if(Number(other.rows[0].count)!==0)return {safe:false,reason:'Another credit invoice exists for this customer. No cleanup permitted.'};
  const voids=await client.query('select 1 from public.sc_credit_voids where invoice_id=$1',[r.id]);
  if(voids.rowCount)return {safe:false,reason:'Invoice has already been voided. No automatic cleanup permitted.'};
  // Lock precisely the customer's payment rows. Guard count, method, and
  // amount: don't touch a payment if it may belong to real business.
  const payments=await client.query(`select id,amount,method,created_at from public.sc_credit_payments
    where lower(trim(customer_name))=lower(trim($1)) for update`,[spec.customer]);
  const actual=payments.rows.map(p=>testCreditMoney(p.amount)).sort((a,b)=>a-b);
  const expected=spec.later.map(testCreditMoney).sort((a,b)=>a-b);
  if(actual.length!==expected.length||actual.some((v,i)=>v!==expected[i])||
     payments.rows.some(p=>p.method!=='Cash'))
    return {safe:false,reason:'Saved payments differ from the exact test transactions; none will be deleted.'};
  // Existing print tracking is a business audit: do not erase or orphan it.
  const printed=await client.query('select count(*)::int as count from public.pos_print_requests where invoice_id=$1',[r.id]);
  if(Number(printed.rows[0].count)!==0)return {safe:false,reason:'Print tracking exists for this invoice. Contact developer for reconciled cleanup.'};
  // Other invoice links may exist; PostgreSQL FKs will also block deletion and
  // roll everything back rather than deleting unrelated records.
  return {safe:true,invoiceId:r.id,invoiceNo,customerName:spec.customer,
    grandTotal:spec.total,amountPaidAtSale:spec.atSale,
    laterPayments:payments.rows.map(p=>({id:p.id,amount:Number(p.amount),method:p.method})),
    removeInvoice:true,removeCreditEntry:true,removeLaterPaymentCount:payments.rowCount};
}
app.get('/api/admin/test-credit-cleanup/preview',auth,adminOnly,async(req,res)=>{
  const invoiceNo=String(req.query.invoiceNo||'').trim();
  if(!Object.hasOwn(approvedTestCreditCleanup,invoiceNo))return res.status(400).json({error:'Only SC-PC-2400 and SC-PC-2402 are eligible.'});
  const client=await pool.connect();
  try{
    await client.query('begin');
    const result=await inspectApprovedTestCredit(client,invoiceNo);
    await client.query('rollback');
    res.setHeader('Cache-Control','no-store');
    return res.json(result);
  }catch(e){try{await client.query('rollback')}catch(_){}console.error('Test cleanup preview error',e);return res.status(503).json({error:'Cannot verify all required database records. No records changed.'});}
  finally{client.release();}
});
app.post('/api/admin/test-credit-cleanup',auth,adminOnly,async(req,res)=>{
  // Require an explicit same-origin JSON POST; the admin login session is
  // mandatory, and the exact invoice number must be typed twice.
  const origin=req.get('origin')||'';
  let matchingOrigin=false;
  try{matchingOrigin=new URL(origin).host===req.get('host')&&
    ['https:','http:'].includes(new URL(origin).protocol);}catch(_){}
  if(!matchingOrigin||!req.is('application/json'))return res.status(403).json({error:'Open the cleanup page on the Star Chicken website.'});
  const invoiceNo=String(req.body?.invoiceNo||'').trim();
  const confirmation=String(req.body?.confirmation||'').trim();
  if(!Object.hasOwn(approvedTestCreditCleanup,invoiceNo)||confirmation!==`DELETE TEST ${invoiceNo}`)
    return res.status(400).json({error:'Incorrect confirmation or invoice not eligible.'});
  const client=await pool.connect();
  try{
    await client.query('begin');
    const result=await inspectApprovedTestCredit(client,invoiceNo);
    if(!result.safe){await client.query('rollback');return res.status(409).json({error:result.reason});}
    // Delete only the identified payment IDs; check exact affected row counts.
    for(const p of result.laterPayments){
      const d=await client.query('delete from public.sc_credit_payments where id=$1',[p.id]);
      if(d.rowCount!==1)throw new Error('Payment deletion count mismatch');
    }
    const credit=await client.query('delete from public.sc_credit_invoices where invoice_id=$1',[result.invoiceId]);
    if(credit.rowCount!==1)throw new Error('Credit deletion count mismatch');
    const invoice=await client.query('delete from public.invoices where id=$1',[result.invoiceId]);
    if(invoice.rowCount!==1)throw new Error('Invoice deletion count mismatch');
    // Keep admin identity and cleanup details in the audit trail only.
    await writeAudit(client,req,'admin.test_credit_cleanup',result.invoiceId,result.invoiceNo,{
      customerName:result.customerName,invoiceTotal:result.grandTotal,
      atSale:result.amountPaidAtSale,laterPaymentsDeleted:result.laterPayments.map(p=>p.amount),
      reason:'User-confirmed removal of November 14 test records'});
    await client.query('commit');
    scPublishInvoiceChange('deleted',invoiceNo);
    res.setHeader('Cache-Control','no-store');
    return res.json({ok:true,invoiceNo,customerName:result.customerName,
      deletedLaterPayments:result.removeLaterPaymentCount,
      invoiceCounterUnchanged:true});
  }catch(e){try{await client.query('rollback')}catch(_){}console.error('Admin test cleanup failed',e);
    return res.status(503).json({error:'Cleanup aborted and transaction rolled back. No partial deletion. Check Render logs before retrying.'});}
  finally{client.release();}
});
app.get('/admin/test-credit-cleanup',auth,adminOnly,(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Star Chicken — Test Credit Cleanup</title>
<style>body{font:16px system-ui,Arial;background:#fff8e8;color:#242424;margin:0;padding:24px}
main{max-width:750px;margin:auto;background:white;border:1px solid #edd7b6;border-radius:14px;padding:24px;box-shadow:0 4px 20px #0001}
h1{color:#b71c1c;font-size:1.4rem}label{font-weight:700;display:block;margin:18px 0 6px}select,input,button{font:inherit;padding:12px;border:1px solid #bbb;border-radius:8px;max-width:100%;box-sizing:border-box}
select,input{width:100%}button{background:#bb1c24;color:white;border:0;cursor:pointer;margin-top:12px}button:disabled{opacity:.5;cursor:not-allowed}pre{white-space:pre-wrap;word-break:break-word;background:#f7f7f7;padding:15px;border-radius:8px}
small,.hint{color:#555}#status{font-weight:700;margin-top:20px}a{color:#b71c1c}</style></head><body><main>
<h1>Star Chicken — Remove TWO known test invoices</h1><p>This Admin-only tool is strictly limited to <strong>SC-PC-2400 (K & K Biryani and Fast Food)</strong> and <strong>SC-PC-2402 (Liaqat Ali)</strong>.</p>
<p>Choose one invoice, check its exact saved details, then type the confirmation. This permanently deletes the selected original invoice, its credit entry, and its exact later test payments. It does <strong>not</strong> delete the customer or reuse the invoice number. An Admin audit record is retained.</p>
<label for="which">Test invoice to review</label><select id="which"><option value="SC-PC-2400">SC-PC-2400 — K & K Biryani and Fast Food</option><option value="SC-PC-2402">SC-PC-2402 — Liaqat Ali</option></select>
<button id="preview" type="button">Review saved records</button><pre id="details">Click Review saved records.</pre>
<label for="confirm">Type the exact confirmation displayed after review</label><input id="confirm" autocomplete="off" spellcheck="false" placeholder="Review first" disabled>
<button id="remove" type="button" disabled>Permanently delete this test invoice and payments</button>
<p class="hint">If the real database has any different amounts, other credit invoices, other payments, voids, or print tracking, cleanup will be blocked. No database setup SQL is needed.</p>
<div id="status" role="status"></div><p><a href="/">Return to Star Chicken POS</a></p></main>
<script>
const which=document.getElementById('which'),preview=document.getElementById('preview'),details=document.getElementById('details'),confirmInput=document.getElementById('confirm'),remove=document.getElementById('remove'),status=document.getElementById('status');
let approved='';function reset(){approved='';confirmInput.value='';confirmInput.disabled=true;remove.disabled=true;details.textContent='Click Review saved records.';status.textContent='';}
which.addEventListener('change',reset);
preview.addEventListener('click',async()=>{reset();preview.disabled=true;status.textContent='Checking cloud records…';
try{const r=await fetch('/api/admin/test-credit-cleanup/preview?invoiceNo='+encodeURIComponent(which.value),{credentials:'same-origin',cache:'no-store'});const d=await r.json();
if(!r.ok)throw new Error(d.error||'Preview failed');if(!d.safe){details.textContent='Blocked: '+d.reason;status.textContent='NOT SAFE TO DELETE';return;}
approved=d.invoiceNo;details.textContent='Invoice: '+d.invoiceNo+'\\nCustomer: '+d.customerName+'\\nInvoice total: Rs '+d.grandTotal+'\\nPaid at sale: Rs '+d.amountPaidAtSale+'\\nLater payments: '+d.laterPayments.map(p=>'Rs '+p.amount+' ('+p.method+')').join(', ')+'\\n\\nType: DELETE TEST '+approved;
confirmInput.disabled=false;remove.disabled=false;status.textContent='Verified. Review before confirming.';
}catch(e){status.textContent='Error: '+e.message;}finally{preview.disabled=false;}});
remove.addEventListener('click',async()=>{if(!approved||approved!==which.value){reset();return;}
if(confirmInput.value.trim()!=='DELETE TEST '+approved){status.textContent='Confirmation text does not match';return;}
if(!window.confirm('PERMANENTLY DELETE '+approved+' and its exact test payments? This cannot be undone.'))return;
remove.disabled=true;status.textContent='Deleting verified test records…';
try{const r=await fetch('/api/admin/test-credit-cleanup',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({invoiceNo:approved,confirmation:confirmInput.value.trim()})});const d=await r.json();
if(!r.ok)throw new Error(d.error||'Cleanup failed');status.textContent='DONE: '+d.invoiceNo+' and '+d.deletedLaterPayments+' later payments removed. Invoice numbering unchanged. Now refresh the POS ledger.';details.textContent=JSON.stringify(d,null,2);confirmInput.disabled=true;approved='';
}catch(e){status.textContent='CLEANUP NOT COMPLETED: '+e.message;remove.disabled=false;}});
</script></body></html>`);
});

/* ---------- Instant invoice change notifications (Server-Sent Events) ----------
   Runs in this Node process. It does not poll Supabase or download invoices.
   Notify only AFTER a successful invoice transaction commit. The client
   reloads invoice data when it receives a change event.
   NOTE: for multiple Render instances, use a shared broker such as Redis.
*/
const scInvoiceEventClients = new Set();
let scInvoiceEventVersion = 0;
function scPublishInvoiceChange(action, invoiceNo) {
  scInvoiceListCache.invalidate();
  scInvoiceEventVersion += 1;
  const payload = JSON.stringify({version:scInvoiceEventVersion,action,invoiceNo:String(invoiceNo||'')});
  for (const response of scInvoiceEventClients) {
    try { response.write('event: invoice-change\ndata: '+payload+'\n\n'); }
    catch (_) { scInvoiceEventClients.delete(response); }
  }
}
app.get('/api/invoices/events', auth, (req,res) => {
  if (!readRoleIdentity(req)) return res.status(403).json({error:'POS Staff or Admin login required'});
  res.status(200);
  res.setHeader('Content-Type','text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control','no-cache, no-transform');
  res.setHeader('Connection','keep-alive');
  res.setHeader('X-Accel-Buffering','no');
  res.flushHeaders?.();
  res.write(': connected\n\n');
  scInvoiceEventClients.add(res);
  const heartbeat = setInterval(() => {
    try { res.write(': heartbeat\n\n'); }
    catch (_) { clearInterval(heartbeat); scInvoiceEventClients.delete(res); }
  }, 45000);
  req.on('close',()=>{clearInterval(heartbeat);scInvoiceEventClients.delete(res);});
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
    const invoices=await scInvoiceListCache.get(async()=>{
      const result = await pool.query(`
      select i.id, i.invoice_no, i.invoice_date, i.invoice_time,
             i.customer_name, i.shop_name, i.bill_maker, i.customer_phone,
             i.items, i.discount, i.subtotal, i.grand_total, i.amount_paid,
             i.balance, i.saved_at, c.invoice_id as credit_invoice_id
      from public.invoices i
      left join public.sc_credit_invoices c on c.invoice_id=i.id
      where not exists(select 1 from public.sc_credit_voids v where v.invoice_id=i.id)
      order by i.saved_at desc, i.updated_at desc
    `);
    return result.rows.map(dbRowToInvoice);
    });
    res.setHeader('Cache-Control','no-store');
    res.json(invoices);
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
      and not exists(select 1 from public.sc_credit_voids v where v.invoice_id=i.id)
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
      if(readRoleIdentity(req)?.role!=='admin'){await client.query('rollback');return res.status(403).json({error:'Only Admin can edit a saved invoice'});}
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
      try { await scEnforceNewInvoicePrices(client,inv,readRoleIdentity(req)||{}); }
      catch(priceError){await client.query('rollback');return res.status(400).json({error:priceError.message});}
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
    scPublishInvoiceChange(existing.rowCount?'updated':'created',inv.invoiceNo);
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
    scPublishInvoiceChange('deleted',found.rows[0].invoice_no);
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
    scPublishInvoiceChange('bulk-import','');
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
  add('Payment Type: ' + (row.is_credit ? 'CREDIT' : 'CASH'), {bold:true});
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
    const found = await pool.query(`select id,invoice_no from public.invoices i where id=$1
      and not exists(select 1 from public.sc_credit_voids v where v.invoice_id=i.id)`,[id]);
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
      amount_paid, balance,
      exists(select 1 from public.sc_credit_invoices c where c.invoice_id=i.id) as is_credit
      from public.invoices i where id=$1
      and not exists(select 1 from public.sc_credit_voids v where v.invoice_id=i.id)`,[payload.invoiceId]);
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
