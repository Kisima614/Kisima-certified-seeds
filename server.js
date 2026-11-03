
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');
const path = require('path');

const required = ['DATABASE_URL', 'ADMIN_PASSWORD', 'JWT_SECRET'];

for (const k of required) {
  if (!process.env[k]) {
    console.error(`Missing required environment variable: ${k}`);
    process.exit(1);
  }
}

if (process.env.NODE_ENV === 'production' &&
    process.env.ADMIN_PASSWORD.length < 14) {
  console.error('ADMIN_PASSWORD must be at least 14 characters in production.');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));

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

    ALTER TABLE orders ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT '';
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS paystack_reference TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_phone TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS mpesa_receipt TEXT;
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

function makeOrderId() {
  return 'KS' +
    Date.now().toString().slice(-8) +
    Math.random().toString(36).slice(2, 6).toUpperCase();
}

function makePaystackReference() {
  return 'KISIMA-' + crypto.randomBytes(12).toString('hex');
}

function paystackKey() {
  const key = process.env.PAYSTACK_SECRET_KEY;
  if (!key) throw new Error('Paystack secret key is not configured.');
  return key;
}

async function paystackRequest(endpoint, options = {}) {
  const response = await fetch(
    `https://api.paystack.co${endpoint}`,
    {
      ...options,
      headers: {
        Authorization: `Bearer ${paystackKey()}`,
        'Content-Type': 'application/json',
        ...(options.headers || {})
      }
    }
  );

  const data = await response.json();

  if (!response.ok || !data.status) {
    console.error('Paystack API error:', data.message || 'Unknown error');
    throw new Error(data.message || 'Paystack request failed.');
  }

  return data.data;
}

async function verifyPaystackPayment(reference, expectedTotal) {
  const data = await paystackRequest(
    `/transaction/verify/${encodeURIComponent(reference)}`
  );

  if (
    data.status !== 'success' ||
    data.currency !== 'KES' ||
    Number(data.amount) !== Number(expectedTotal) * 100
  ) {
    return false;
  }

  return data;
}

async function markPaystackOrderPaid(reference, paymentData) {
  const result = await pool.query(
    `SELECT id, total, payment_status
     FROM orders
     WHERE paystack_reference = $1`,
    [reference]
  );

  if (!result.rowCount) {
    console.warn('Unknown Paystack reference:', reference);
    return;
  }

  const order = result.rows[0];

  if (order.payment_status === 'Verified') return;

  const verified = await verifyPaystackPayment(
    reference,
    order.total
  );

  if (!verified) {
    console.error('Paystack payment verification failed:', reference);
    return;
  }

  await pool.query(
    `UPDATE orders
     SET payment_status = 'Verified',
         mpesa_ref = $2,
         mpesa_receipt = $2
     WHERE id = $1
       AND paystack_reference = $3
       AND payment_status <> 'Verified'`,
    [
      order.id,
      clean(paymentData?.receipt || reference, 40),
      reference
    ]
  );

  console.log('Paystack payment verified for order:', order.id);
}

/*
  Paystack webhook.
  This route must be registered BEFORE express.json()
  so that the original request body can be verified.
*/
app.post(
  '/api/paystack/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    try {
      const signature = req.headers['x-paystack-signature'];

      if (!signature || !Buffer.isBuffer(req.body)) {
        return res.sendStatus(400);
      }

      const expected = crypto
        .createHmac('sha512', paystackKey())
        .update(req.body)
        .digest('hex');

      const suppliedBuffer = Buffer.from(String(signature), 'hex');
      const expectedBuffer = Buffer.from(expected, 'hex');

      if (
        suppliedBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)
      ) {
        console.warn('Invalid Paystack webhook signature.');
        return res.sendStatus(401);
      }

      const event = JSON.parse(req.body.toString('utf8'));

      if (event.event === 'charge.success' && event.data?.reference) {
        await markPaystackOrderPaid(
          event.data.reference,
          event.data
        );
      }

      return res.sendStatus(200);

    } catch (e) {
      console.error('Paystack webhook error:', e.message);
      return res.sendStatus(500);
    }
  }
);

app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* Health check */
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false });
  }
});

/* Products and prices */
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
  const email = clean(b.email, 200).toLowerCase();
  const location = clean(b.location, 220);
  const variety = clean(b.variety, 100);
  const seedClass = clean(b.seedClass, 50);
  const delivery = clean(b.delivery, 100);
  const mpesa = clean(b.mpesa, 40).toUpperCase();
  const notes = clean(b.notes, 500);
  const bags = Number(b.bags);

  if (
    !customer || !phone || !email || !location ||
    !variety || !seedClass || !delivery || !mpesa ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    !Number.isInteger(bags) || bags < 1 || bags > 500
  ) {
    return res.status(400).json({
      error: 'Please complete all required fields correctly.'
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
       (id, customer, phone, email, location, seed_class, variety,
        bags, delivery, mpesa_ref, notes, unit_price, total)
       VALUES
       ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [
        id, customer, phone, email, location, seedClass,
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

/* Paystack M-Pesa payment */
app.post('/api/orders/paystack', async (req, res) => {
  const b = req.body || {};

  const customer = clean(b.customer, 100);
  const phoneRaw = clean(b.phone, 40);
  const phone = normalizeKenyanPhone(phoneRaw);
  const email = clean(b.email, 200).toLowerCase();
  const location = clean(b.location, 220);
  const variety = clean(b.variety, 100);
  const seedClass = clean(b.seedClass, 50);
  const delivery = clean(b.delivery, 100);
  const notes = clean(b.notes, 500);
  const bags = Number(b.bags);

  if (
    !customer || !phone || !email || !location ||
    !variety || !seedClass || !delivery ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    !Number.isInteger(bags) || bags < 1 || bags > 500
  ) {
    return res.status(400).json({
      error: 'Complete all fields and enter a valid email and Kenyan M-Pesa phone number.'
    });
  }

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

    if (
      !Number.isSafeInteger(total) ||
      total < 1 ||
      total > 150000
    ) {
      return res.status(400).json({
        error: 'The order total must be between KSh 1 and KSh 150,000 for this M-Pesa payment.'
      });
    }

    const id = makeOrderId();
    const reference = makePaystackReference();

    await pool.query(
      `INSERT INTO orders
       (id, customer, phone, email, location, seed_class, variety,
        bags, delivery, notes, unit_price, total, payment_status,
        payment_phone, paystack_reference)
       VALUES
       ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
        'Pending verification',$13,$14)`,
      [
        id, customer, phoneRaw, email, location, seedClass,
        variety, bags, delivery, notes, p.price, total,
        phone, reference
      ]
    );

    const charge = await paystackRequest('/charge', {
      method: 'POST',
      body: JSON.stringify({
        email,
        amount: String(total * 100),
        currency: 'KES',
        reference,
        mobile_money: {
          phone: '+' + phone,
          provider: 'mpesa'
        },
        metadata: {
          order_id: id,
          business: 'Kisima Certified Seeds'
        }
      })
    });

    if (
      !charge.reference ||
      !['pay_offline', 'pending', 'success'].includes(charge.status)
    ) {
      throw new Error(
        charge.display_text || 'Paystack could not start the M-Pesa payment.'
      );
    }

    if (charge.status === 'success') {
      await markPaystackOrderPaid(reference, charge);
    }

    return res.status(202).json({
      id,
      reference,
      total,
      paymentStatus: 'Pending verification',
      message: charge.display_text ||
        'Check your phone and complete the M-Pesa payment prompt.'
    });

  } catch (e) {
    console.error('PAYSTACK INITIATION ERROR:', e.message);
    return res.status(502).json({
      error: 'Paystack could not start the M-Pesa payment. Please try again or contact Kisima.'
    });
  }
});

/* Customer payment status check */
app.get('/api/orders/:id/payment', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, total,
              payment_status AS "paymentStatus",
              mpesa_receipt AS receipt,
              paystack_reference AS reference
       FROM orders
       WHERE id = $1`,
      [clean(req.params.id, 40)]
    );

    if (!r.rowCount) {
      return res.status(404).json({ error: 'Order not found.' });
    }

    const order = r.rows[0];

    if (
      order.reference &&
      order.paymentStatus !== 'Verified'
    ) {
      try {
        const verified = await verifyPaystackPayment(
          order.reference,
          order.total
        );

        if (verified) {
          await markPaystackOrderPaid(order.reference, verified);

          const updated = await pool.query(
            `SELECT payment_status AS "paymentStatus",
                    mpesa_receipt AS receipt
             FROM orders WHERE id = $1`,
            [order.id]
          );

          return res.json({
            id: order.id,
            ...updated.rows[0]
          });
        }
      } catch (e) {
        console.error('Paystack status check:', e.message);
      }
    }

    res.json({
      id: order.id,
      paymentStatus: order.paymentStatus,
      receipt: order.receipt
    });

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
      `SELECT id, customer, phone, email, location,
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
