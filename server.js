
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const required = ['DATABASE_URL', 'ADMIN_PASSWORD', 'JWT_SECRET'];
for (const k of required) {
  if (!process.env[k]) {
    console.error(`Missing required environment variable: ${k}`);
    process.exit(1);
  }
}

if (process.env.NODE_ENV === 'production' && process.env.ADMIN_PASSWORD.length < 14) {
  console.error('ADMIN_PASSWORD must be at least 14 characters in production.');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/', rateLimit({
  windowMs: 60000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false'
    ? false
    : { rejectUnauthorized: false }
});

const seed = [
  ['Unica', 3750, true],
  ['Shangi', 3750, true],
  ['Super Shangi', 3750, true],
  ['White Shangi', 3750, true],
  ['Dutch', 3750, true],
  ['Sheherekea', 3750, true],
  ['Stephen', 3750, true],
  ['Markies', 3750, true]
];

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      price INTEGER NOT NULL CHECK(price >= 0),
      available BOOLEAN NOT NULL DEFAULT true,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY,
      customer TEXT NOT NULL,
      phone TEXT NOT NULL,
      location TEXT NOT NULL,
      seed_class TEXT NOT NULL,
      variety TEXT NOT NULL,
      bags INTEGER NOT NULL CHECK(bags BETWEEN 1 AND 500),
      delivery TEXT NOT NULL,
      mpesa_ref TEXT NOT NULL DEFAULT '',
      notes TEXT DEFAULT '',
      unit_price INTEGER NOT NULL,
      total INTEGER NOT NULL,
      payment_status TEXT NOT NULL DEFAULT 'Pending verification',
      delivery_status TEXT NOT NULL DEFAULT 'Order received',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE orders ADD COLUMN IF NOT EXISTS checkout_request_id TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS merchant_request_id TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS mpesa_receipt TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_phone TEXT;
  `);

  for (const [name, price, available] of seed) {
    await pool.query(
      `INSERT INTO products(name, price, available)
       VALUES($1, $2, $3)
       ON CONFLICT(name) DO UPDATE
       SET price = EXCLUDED.price,
           available = EXCLUDED.available`,
      [name, price, available]
    );
  }
}

const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);

function auth(req, res, next) {
  const token = (req.headers.authorization || '')
    .replace(/^Bearer\s+/i, '');

  try {
    const data = jwt.verify(token, process.env.JWT_SECRET);
    if (data.role !== 'admin') throw new Error('role');
    req.admin = true;
    next();
  } catch {
    return res.status(401).json({
      error: 'Please sign in as administrator.'
    });
  }
}

const clean = (v, max = 200) =>
  String(v ?? '').trim().slice(0, max);

function normalizeKenyanPhone(value) {
  let p = String(value || '').replace(/[^\d+]/g, '');

  if (p.startsWith('+')) p = p.slice(1);
  if (p.startsWith('0')) p = '254' + p.slice(1);
  if (p.startsWith('7') || p.startsWith('1')) p = '254' + p;

  return /^254[17]\d{8}$/.test(p) ? p : null;
}

function darajaConfig() {
  const env = (process.env.DARAJA_ENV || 'sandbox').toLowerCase();

  if (!['sandbox', 'production'].includes(env)) {
    throw new Error('Invalid DARAJA_ENV');
  }

  const requiredKeys = [
    'DARAJA_CONSUMER_KEY',
    'DARAJA_CONSUMER_SECRET',
    'DARAJA_SHORTCODE',
    'DARAJA_PASSKEY'
  ];

  for (const k of requiredKeys) {
    if (!process.env[k]) throw new Error(`Missing ${k}`);
  }

  const base = env === 'production'
    ? 'https://api.safaricom.co.ke'
    : 'https://sandbox.safaricom.co.ke';

  const shortcode = process.env.DARAJA_SHORTCODE;

  const callback = process.env.DARAJA_CALLBACK_URL ||
    'https://kisima-certified-seeds.onrender.com/api/mpesa/callback';

  if (!callback.startsWith('https://')) {
    throw new Error('DARAJA_CALLBACK_URL must be HTTPS');
  }

  return {
    base,
    shortcode,
    passkey: process.env.DARAJA_PASSKEY,
    key: process.env.DARAJA_CONSUMER_KEY,
    secret: process.env.DARAJA_CONSUMER_SECRET,
    callback
  };
}

async function darajaToken(cfg) {
  const authHeader = Buffer
    .from(`${cfg.key}:${cfg.secret}`)
    .toString('base64');

  const response = await fetch(
    `${cfg.base}/oauth/v1/generate?grant_type=client_credentials`,
    {
      headers: {
        Authorization: `Basic ${authHeader}`
      }
    }
  );

  const data = await response.json();

  if (!response.ok || !data.access_token) {
    console.error('Daraja token error:', data);
    throw new Error(
      'Could not authenticate with M-Pesa. Check Daraja credentials and app permissions.'
    );
  }

  return data.access_token;
}

function makeOrderId() {
  return 'KS' +
    Date.now().toString().slice(-8) +
    Math.random().toString(36).slice(2, 6).toUpperCase();
}

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false });
  }
});

app.get('/api/products', async (_req, res) => {
  try {
    const r = await pool.query(
      'SELECT id, name, price, available FROM products ORDER BY id'
    );
    res.json(r.rows);
  } catch {
    res.status(500).json({ error: 'Could not load products.' });
  }
});

/* Manual M-Pesa payment fallback */
app.post('/api/orders', async (req, res) => {
  const b = req.body || {};

  const customer = clean(b.customer, 100);
  const phone = clean(b.phone, 40);
  const location = clean(b.location, 220);
  const variety = clean(b.variety, 100);
  const seedClass = clean(b.seedClass, 50);
  const delivery = clean(b.delivery, 100);
  const mpesa = clean(b.mpesa, 40).toUpperCase();
  const notes = clean(b.notes, 500);
  const bags = Number(b.bags);

  if (
    !customer || !phone || !location || !variety ||
    !seedClass || !delivery || !mpesa ||
    !Number.isInteger(bags) || bags < 1 || bags > 500
  ) {
    return res.status(400).json({
      error: 'Please complete all required fields with a valid bag quantity.'
    });
  }

  if (!/^[A-Z0-9]{8,15}$/.test(mpesa)) {
    return res.status(400).json({
      error: 'Check the M-Pesa transaction reference format.'
    });
  }

  try {
    const pr = await pool.query(
      'SELECT name, price, available FROM products WHERE name = $1',
      [variety]
    );

    if (!pr.rowCount || !pr.rows[0].available) {
      return res.status(400).json({
        error: 'This variety is not currently available to order. Please contact Kisima.'
      });
    }

    const p = pr.rows[0];
    const id = makeOrderId();
    const total = p.price * bags;

    await pool.query(
      `INSERT INTO orders
       (id, customer, phone, location, seed_class, variety,
        bags, delivery, mpesa_ref, notes, unit_price, total)
       VALUES
       ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        id, customer, phone, location, seedClass,
        variety, bags, delivery, mpesa, notes, p.price, total
      ]
    );

    res.status(201).json({
      id,
      total,
      unitPrice: p.price,
      paymentStatus: 'Pending verification',
      message: 'Order received. Payment is pending manual verification.'
    });
  } catch (e) {
    console.error('ORDER SAVE ERROR:', e.message);
    res.status(500).json({
      error: 'Could not save order. Please try again or contact Kisima.'
    });
  }
});

/* M-Pesa STK Push order */
app.post('/api/orders/stk', async (req, res) => {
  const b = req.body || {};

  const customer = clean(b.customer, 100);
  const phoneRaw = clean(b.phone, 40);
  const location = clean(b.location, 220);
  const phone = normalizeKenyanPhone(phoneRaw);
  const variety = clean(b.variety, 100);
  const seedClass = clean(b.seedClass, 50);
  const delivery = clean(b.delivery, 100);
  const notes = clean(b.notes, 500);
  const bags = Number(b.bags);

  if (
    !customer || !phone || !location || !variety ||
    !seedClass || !delivery ||
    !Number.isInteger(bags) || bags < 1 || bags > 500
  ) {
    return res.status(400).json({
      error: 'Complete all fields and enter a valid Kenyan M-Pesa phone number.'
    });
  }

  if (!['C1', 'C2', 'Generation 1', 'Basic', 'Prebasic'].includes(seedClass)) {
    return res.status(400).json({
      error: 'Select a valid seed class.'
    });
  }

  let orderId;

  try {
    const pr = await pool.query(
      'SELECT name, price, available FROM products WHERE name = $1',
      [variety]
    );

    if (!pr.rowCount || !pr.rows[0].available) {
      return res.status(400).json({
        error: 'This variety is not currently available. Please contact Kisima.'
      });
    }

    const p = pr.rows[0];
    const total = p.price * bags;

    if (!Number.isSafeInteger(total) || total < 1) {
      return res.status(400).json({ error: 'Invalid order total.' });
    }

    orderId = makeOrderId();

    await pool.query(
      `INSERT INTO orders
       (id, customer, phone, location, seed_class, variety,
        bags, delivery, mpesa_ref, notes, unit_price, total,
        payment_status, payment_phone)
       VALUES
       ($1,$2,$3,$4,$5,$6,$7,$8,'STK_PENDING',$9,$10,$11,
        'Pending verification',$12)`,
      [
        orderId, customer, phoneRaw, location, seedClass,
        variety, bags, delivery, notes, p.price, total, phone
      ]
    );

    const cfg = darajaConfig();

    if (cfg.base.includes('sandbox') && cfg.shortcode !== '174379') {
      throw new Error('Sandbox testing must use shortcode 174379.');
    }

    const token = await darajaToken(cfg);

    const parts = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'Africa/Nairobi',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23'
    }).formatToParts(new Date());

    const part = Object.fromEntries(
      parts.map(x => [x.type, x.value])
    );

    const timestamp =
      part.year + part.month + part.day +
      part.hour + part.minute + part.second;

    const password = Buffer
      .from(`${cfg.shortcode}${cfg.passkey}${timestamp}`)
      .toString('base64');

    const payload = {
      BusinessShortCode: cfg.shortcode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Math.round(total),
      PartyA: phone,
      PartyB: cfg.shortcode,
      PhoneNumber: phone,
      CallBackURL: cfg.callback,
      AccountReference: orderId,
      TransactionDesc: `Kisima seed order ${orderId}`.slice(0, 100)
    };

    const response = await fetch(
      `${cfg.base}/mpesa/stkpush/v1/processrequest`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      }
    );

    const data = await response.json();

    if (
      !response.ok ||
      data.ResponseCode !== '0' ||
      !data.CheckoutRequestID
    ) {
      console.error('Daraja STK request failed:', data);

      await pool.query(
        `UPDATE orders
         SET payment_status = 'Rejected',
             notes = CONCAT(COALESCE(notes,''), $2)
         WHERE id = $1`,
        [orderId, ' | STK request could not be initiated.']
      );

      return res.status(502).json({
        error: data.errorMessage ||
          data.ResponseDescription ||
          'M-Pesa could not start the payment prompt. Your order was saved; please contact Kisima.'
      });
    }

    await pool.query(
      `UPDATE orders
       SET checkout_request_id = $2,
           merchant_request_id = $3
       WHERE id = $1`,
      [
        orderId,
        data.CheckoutRequestID,
        data.MerchantRequestID || null
      ]
    );

    res.status(202).json({
      id: orderId,
      total,
      paymentStatus: 'Pending verification',
      message: 'Payment prompt sent. Enter your M-Pesa PIN on your phone to complete payment.'
    });

  } catch (e) {
    console.error('STK INITIATION ERROR:', e.message);

    if (orderId) {
      try {
        await pool.query(
          `UPDATE orders
           SET notes = CONCAT(COALESCE(notes,''), $2)
           WHERE id = $1`,
          [
            orderId,
            ' | STK initiation error; manual payment follow-up required.'
          ]
        );
      } catch {}
    }

    res.status(500).json({
      error: 'Could not start M-Pesa payment. Your order may have been saved; contact Kisima before placing it again.'
    });
  }
});

/* Safaricom payment callback */
app.post('/api/mpesa/callback', async (req, res) => {
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

  const cb = req.body?.Body?.stkCallback;
  if (!cb?.CheckoutRequestID) return;

  try {
    const found = await pool.query(
      `SELECT id, total, payment_phone, payment_status
       FROM orders
       WHERE checkout_request_id = $1`,
      [cb.CheckoutRequestID]
    );

    if (!found.rowCount) {
      console.warn(
        'M-Pesa callback for unknown CheckoutRequestID:',
        cb.CheckoutRequestID
      );
      return;
    }

    const order = found.rows[0];

    if (order.payment_status === 'Verified') return;

    if (Number(cb.ResultCode) !== 0) {
      await pool.query(
        `UPDATE orders
         SET payment_status = 'Rejected'
         WHERE id = $1 AND payment_status <> 'Verified'`,
        [order.id]
      );

      console.log(
        'STK payment failed for order',
        order.id,
        cb.ResultDesc
      );
      return;
    }

    const items = cb.CallbackMetadata?.Item || [];
    const meta = {};

    for (const item of items) {
      if (item?.Name) meta[item.Name] = item.Value;
    }

    const paidAmount = Number(meta.Amount);
    const receipt = clean(meta.MpesaReceiptNumber, 40);
    const paidPhone = String(meta.PhoneNumber || '');

    if (
      !receipt ||
      paidAmount !== Number(order.total) ||
      paidPhone !== String(order.payment_phone)
    ) {
      console.error(
        'M-Pesa callback did not match order amount/phone:',
        order.id
      );
      return;
    }

    await pool.query(
      `UPDATE orders
       SET payment_status = 'Verified',
           mpesa_ref = $2,
           mpesa_receipt = $2
       WHERE id = $1 AND checkout_request_id = $3`,
      [order.id, receipt, cb.CheckoutRequestID]
    );

    console.log(
      'M-Pesa payment verified for order',
      order.id,
      'receipt',
      receipt
    );

  } catch (e) {
    console.error('M-Pesa callback processing error:', e.message);
  }
});

/* Customer payment status check */
app.get('/api/orders/:id/payment', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id,
              payment_status AS "paymentStatus",
              mpesa_receipt AS receipt
       FROM orders
       WHERE id = $1`,
      [clean(req.params.id, 40)]
    );

    if (!r.rowCount) {
      return res.status(404).json({ error: 'Order not found.' });
    }

    res.json(r.rows[0]);

  } catch {
    res.status(500).json({
      error: 'Could not check payment status.'
    });
  }
});

/* Customer order lookup */
app.post('/api/orders/lookup', async (req, res) => {
  const phone = clean(req.body?.phone, 40).replace(/\s/g, '');

  if (phone.length < 7) {
    return res.status(400).json({
      error: 'Enter the phone number used for the order.'
    });
  }

  try {
    const r = await pool.query(
      `SELECT id, customer, location,
              seed_class AS "seedClass",
              variety, bags, delivery, total,
              payment_status AS "paymentStatus",
              delivery_status AS "deliveryStatus",
              created_at AS created
       FROM orders
       WHERE regexp_replace(phone, '\\s', '', 'g') = $1
       ORDER BY created_at DESC
       LIMIT 30`,
      [phone]
    );

    res.json(r.rows);

  } catch {
    res.status(500).json({
      error: 'Could not look up orders.'
    });
  }
});

/* Administrator login */
app.post('/api/admin/login', async (req, res) => {
  const password = String(req.body?.password || '');

  if (
    password.length > 200 ||
    !await bcrypt.compare(password, adminHash)
  ) {
    return res.status(401).json({
      error: 'Invalid administrator password.'
    });
  }

  const token = jwt.sign(
    { role: 'admin' },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  );

  res.json({ token, expiresIn: 28800 });
});

/* Administrator order list */
app.get('/api/admin/orders', auth, async (_req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, customer, phone, location,
              seed_class AS "seedClass",
              variety, bags, delivery,
              mpesa_ref AS "mpesaRef",
              mpesa_receipt AS "mpesaReceipt",
              notes,
              unit_price AS "unitPrice",
              total,
              payment_status AS "paymentStatus",
              delivery_status AS "deliveryStatus",
              created_at AS created
       FROM orders
       ORDER BY created_at DESC
       LIMIT 500`
    );

    res.json(r.rows);

  } catch {
    res.status(500).json({
      error: 'Could not load orders.'
    });
  }
});

/* Administrator update order statuses */
app.patch('/api/admin/orders/:id', auth, async (req, res) => {
  const pay = [
    'Pending verification',
    'Verified',
    'Rejected'
  ].includes(req.body?.paymentStatus)
    ? req.body.paymentStatus
    : null;

  const del = [
    'Order received',
    'Preparing',
    'Dispatched',
    'Delivered'
  ].includes(req.body?.deliveryStatus)
    ? req.body.deliveryStatus
    : null;

  if (!pay && !del) {
    return res.status(400).json({
      error: 'No valid status supplied.'
    });
  }

  try {
    const r = await pool.query(
      `UPDATE orders
       SET payment_status = COALESCE($2, payment_status),
           delivery_status = COALESCE($3, delivery_status)
       WHERE id = $1
       RETURNING id`,
      [req.params.id, pay, del]
    );

    if (!r.rowCount) {
      return res.status(404).json({ error: 'Order not found.' });
    }

    res.json({ ok: true });

  } catch {
    res.status(500).json({
      error: 'Could not update order.'
    });
  }
});

/* Administrator update product price and availability */
app.patch('/api/admin/products/:id', auth, async (req, res) => {
  const price = Number(req.body?.price);
  const available = req.body?.available;

  if (
    !Number.isInteger(price) ||
    price < 0 ||
    price > 10000000 ||
    typeof available !== 'boolean'
  ) {
    return res.status(400).json({
      error: 'Invalid price or availability.'
    });
  }

  try {
    const r = await pool.query(
      `UPDATE products
       SET price = $2,
           available = $3,
           updated_at = NOW()
       WHERE id = $1
       RETURNING id, name, price, available`,
      [req.params.id, price, available]
    );

    if (!r.rowCount) {
      return res.status(404).json({
        error: 'Product not found.'
      });
    }

    res.json(r.rows[0]);

  } catch {
    res.status(500).json({
      error: 'Could not update product.'
    });
  }
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

init()
  .then(() => {
    app.listen(process.env.PORT || 3000, '0.0.0.0', () => {
      console.log('Kisima app running');
    });
  })
  .catch(e => {
    console.error('Database initialization failed:', e.message);
    process.exit(1);
  });
