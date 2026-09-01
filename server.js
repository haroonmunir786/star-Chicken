require('dotenv').config();

const path = require('path');
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

function signSession() {
  return jwt.sign({ role: 'invoice-user' }, process.env.JWT_SECRET, {
    expiresIn: '7d'
  });
}

function auth(req, res, next) {
  const token = req.cookies.sc_session;
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    jwt.verify(token, process.env.JWT_SECRET);
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

app.post('/login', (req, res) => {
  const password = String(req.body?.password || '');
  if (password !== process.env.APP_PASSWORD) {
    return res.status(401).json({ error: 'Incorrect password' });
  }

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
  res.json({ ok: true });
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

  try {
    const result = await pool.query(`
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

    res.status(201).json(dbRowToInvoice(result.rows[0]));
  } catch (e) {
    console.error(e);
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Duplicate invoice number or ID' });
    }
    res.status(500).json({ error: 'Could not save invoice' });
  }
});

app.delete('/api/invoices/:id', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'delete from public.invoices where id = $1',
      [req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Invoice not found' });
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not delete invoice' });
  }
});

/* ---------- One-time migration endpoint ---------- */
app.post('/api/invoices/bulk', auth, async (req, res) => {
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

/* ---------- Serve the protected app ---------- */
app.get('/', auth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'palmcity.html'));
});

app.use((req, res) => {
  res.status(404).send('Not found');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Star Chicken Invoice App running on http://localhost:${PORT}`);
});
