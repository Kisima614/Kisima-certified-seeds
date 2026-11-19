
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');
const path = require('path');

const required = [
  'DATABASE_URL',
  'ADMIN_PASSWORD',
  'JWT_SECRET',
  'ZETUPAY_SECRET_KEY'
];

for (const k of required) {
  if (!process.env[k]) {
    console.error(`Missing required environment variable: ${k}`);
    process.exit(1);
  }
}

if (
  process.env.NODE_ENV === 'production' &&
  process.env.ADMIN_PASSWORD.length < 14
) {
  console.error('ADMIN_PASSWORD must be at least 14 characters.');
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

app.use(express.json({ limit: '100kb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false'
    ? false
    : { rejectUnauthorized: false }
});

// Prices are per 50kg bag.
const CLASS_PRICES = {
  C1: 3750,
  C2: 3450,
  Basic: 4350,
  Prebasic: 4750
};

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

// ================================
// DATABASE INITIALIZATION
// ================================

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
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS potato_size TEXT NOT NULL DEFAULT 'Size 1';

    -- ZetuPay payment columns.
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS zetupay_payment_key TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS zetupay_transaction_id TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS zetupay_reference TEXT;
  `);

  for (const [name, price, available] of seed) {
    await pool.query(
      `INSERT INTO products(name, price, available)
       VALUES($1, $2, $3)
       ON CONFLICT(name) DO UPDATE
       SET available = EXCLUDED.available`,
      [name, price, available]
    );
  }

  console.log('Database initialized.');
}

const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);

// ================================
// AUTHENTICATION
// ================================

function auth(req, res, next) {
  const token = (req.headers.authorization || '')
    .replace(/^Bearer\s+/i, '');

  try {
    const data = jwt.verify(token, process.env.JWT_SECRET);

    if (data.role !== 'admin') {
      throw new Error('Invalid role');
    }

    req.admin = true;
    next();
  } catch {
    return res.status(401).json({
      error: 'Please sign in as administrator.'
    });
  }
}

// ================================
// HELPERS
// ================================

const clean = (v, max = 200) =>
  String(v ?? '').trim().slice(0, max);

function normalizeKenyanPhone(value) {
  let p = String(value || '').replace(/[^\d+]/g, '');

  if (p.startsWith('+')) {
    p = p.slice(1);
  }

  if (p.startsWith('0')) {
    p = '254' + p.slice(1);
  }

  if (p.startsWith('7') || p.startsWith('1')) {
    p = '254' + p;
  }

  return /^254[17]\d{8}$/.test(p) ? p : null;
}

function makeOrderId() {
  return 'KS' +
    Date.now().toString().slice(-8) +
    crypto.randomBytes(3).toString('hex').toUpperCase();
}

function makeZetuPayReference() {
  return 'KISIMA-' + crypto.randomBytes(12).toString('hex');
}

function zetuPayKey() {
  const key = process.env.ZETUPAY_SECRET_KEY;

  if (!key) {
    throw new Error('ZetuPay secret key is not configured.');
  }

  return key;
}

function getAppUrl() {
  return (
    process.env.APP_URL ||
    process.env.RENDER_EXTERNAL_URL ||
    'https://kisimacertifiedseeds.co.ke'
  ).replace(/\/+$/, '');
}

// ================================
// ZETUPAY API
// ================================

async function zetuPayRequest(endpoint, options = {}) {
  const response = await fetch(
    `https://pay.zetupay.co.ke/api/v1${endpoint}`,
    {
      ...options,
      headers: {
        Authorization: `Bearer ${zetuPayKey()}`,
        'Content-Type': 'application/json',
        ...(options.headers || {})
      }
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok || data.success === false) {
    console.error(
      'ZetuPay API error:',
      data.message || data.error || 'Unknown error'
    );

    throw new Error(
      data.message || data.error || 'ZetuPay request failed.'
    );
  }

  return data.data || data;
}

/*
  Fetch the payment directly from ZetuPay.

  This function does not assume that every non-success response
  means a network error. It returns the actual payment status
  when ZetuPay provides one.
*/
async function getZetuPayPayment(paymentKey) {
  if (!paymentKey) {
    return null;
  }

  const response = await fetch(
    `https://pay.zetupay.co.ke/api/v1/payment/${encodeURIComponent(paymentKey)}`,
    {
      method: 'GET',
      headers: {
        Accept: 'application/json'
      },
      cache: 'no-store'
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok || data.success === false) {
    return null;
  }

  return data.data || data;
}

/*
  Successful payments must match:
  - payment status
  - expected amount
  - KES currency
*/
async function verifyZetuPayPayment(paymentKey, expectedTotal) {
  const payment = await getZetuPayPayment(paymentKey);

  if (!payment) {
    return null;
  }

  if (
    payment.status !== 'success' ||
    payment.currency !== 'KES' ||
    Number(payment.amount) !== Number(expectedTotal)
  ) {
    return null;
  }

  return payment;
}

/*
  Mark an order paid only after server-side verification.
*/
async function markZetuPayOrderPaid(paymentKey, paymentData) {
  const result = await pool.query(
    `SELECT id, total, payment_status
     FROM orders
     WHERE zetupay_payment_key = $1`,
    [paymentKey]
  );

  if (!result.rowCount) {
    console.warn('Unknown ZetuPay payment key.');
    return;
  }

  const order = result.rows[0];

  if (order.payment_status === 'Verified') {
    return;
  }

  const verified = await verifyZetuPayPayment(
    paymentKey,
    order.total
  );

  if (!verified) {
    console.error('ZetuPay payment verification failed.');
    return;
  }

  const receipt = clean(
    paymentData?.receiptNumber ||
    paymentData?.receipt ||
    verified?.receiptNumber ||
    verified?.waveTransactionId ||
    paymentKey,
    100
  );

  const transactionId = clean(
    paymentData?.waveTransactionId ||
    verified?.waveTransactionId ||
    '',
    100
  );

  await pool.query(
    `UPDATE orders
     SET payment_status = 'Verified',
         mpesa_ref = $2,
         mpesa_receipt = $2,
         zetupay_transaction_id = $3
     WHERE id = $1
       AND zetupay_payment_key = $4
       AND payment_status <> 'Verified'`,
    [
      order.id,
      receipt,
      transactionId,
      paymentKey
    ]
  );

  console.log('ZetuPay payment verified for order:', order.id);
}

/*
  Update failed/cancelled/expired payments.

  A payment is never marked rejected simply because the
  verification request failed or timed out.
*/
async function updateZetuPayFailedStatus(orderId, payment) {
  const status = String(payment?.status || '').toLowerCase();

  const failedStatuses = [
    'failed',
    'cancelled',
    'canceled',
    'expired'
  ];

  if (!failedStatuses.includes(status)) {
    return false;
  }

  await pool.query(
    `UPDATE orders
     SET payment_status = 'Rejected'
     WHERE id = $1
       AND payment_status <> 'Verified'`,
    [orderId]
  );

  return true;
}

// ================================
// STATIC WEBSITE
// ================================

app.use(express.static(path.join(__dirname, 'public')));

// ================================
// HEALTH CHECK
// ================================

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false });
  }
});

// ================================
// PRODUCTS
// ================================

app.get('/api/products', async (_req, res) => {
  try {
    const r = await pool.query(
      'SELECT id, name, available FROM products ORDER BY id'
    );

    res.json(r.rows);
  } catch {
    res.status(500).json({
      error: 'Could not load products.'
    });
  }
});

// ================================
// ORDER VALIDATION
// ================================

async function getOrderDetails(b) {
  const customer = clean(b.customer, 100);
  const phone = clean(b.phone, 40);
  const email = clean(b.email, 200).toLowerCase();
  const location = clean(b.location, 220);
  const variety = clean(b.variety, 100);
  const seedClass = clean(b.seedClass, 50);
  const potatoSize = clean(b.potatoSize, 20);
  const delivery = clean(b.delivery, 100);
  const notes = clean(b.notes, 500);
  const bags = Number(b.bags);

  if (
    !customer || !phone || !email || !location ||
    !variety || !seedClass || !potatoSize || !delivery ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    !Number.isInteger(bags) || bags < 1 || bags > 500
  ) {
    throw new Error('Please complete all required fields correctly.');
  }

  if (!['Size 1', 'Size 2'].includes(potatoSize)) {
    throw new Error('Please select Size 1 or Size 2.');
  }

  if (!Object.prototype.hasOwnProperty.call(CLASS_PRICES, seedClass)) {
    throw new Error('Please select a valid seed class.');
  }

  if (!['Delivery', 'Collection'].includes(delivery)) {
    throw new Error('Please select a valid delivery method.');
  }

  const pr = await pool.query(
    'SELECT name, available FROM products WHERE name = $1',
    [variety]
  );

  if (!pr.rowCount || !pr.rows[0].available) {
    throw new Error(
      'This variety is not currently available. Please contact Kisima.'
    );
  }

  const unitPrice = CLASS_PRICES[seedClass];
  const total = unitPrice * bags;

  if (!Number.isSafeInteger(total)) {
    throw new Error('Invalid order total.');
  }

  return {
    customer,
    phone,
    email,
    location,
    variety,
    seedClass,
    potatoSize,
    delivery,
    notes,
    bags,
    unitPrice,
    total
  };
}

// ================================
// MANUAL M-PESA ORDERS
// ================================

app.post('/api/orders', async (req, res) => {
  const mpesa = clean(req.body?.mpesa, 40).toUpperCase();

  if (!/^[A-Z0-9]{8,15}$/.test(mpesa)) {
    return res.status(400).json({
      error: 'Check the M-Pesa transaction reference format.'
    });
  }

  try {
    const o = await getOrderDetails(req.body || {});
    const id = makeOrderId();

    await pool.query(
      `INSERT INTO orders
       (id, customer, phone, email, location, seed_class,
        variety, potato_size, bags, delivery, mpesa_ref,
        notes, unit_price, total)
       VALUES
       ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [
        id,
        o.customer,
        o.phone,
        o.email,
        o.location,
        o.seedClass,
        o.variety,
        o.potatoSize,
        o.bags,
        o.delivery,
        mpesa,
        o.notes,
        o.unitPrice,
        o.total
      ]
    );

    return res.status(201).json({
      id,
      total: o.total,
      unitPrice: o.unitPrice,
      paymentStatus: 'Pending verification',
      message: 'Order received. Payment is pending manual verification.'
    });

  } catch (e) {
    console.error('ORDER SAVE ERROR:', e.message);

    return res.status(400).json({
      error: e.message
    });
  }
});

// ================================
// ZETUPAY HOSTED CHECKOUT
// ================================

app.post('/api/orders/zetupay', async (req, res) => {
  let orderId = null;

  try {
    const o = await getOrderDetails(req.body || {});
    const phone = normalizeKenyanPhone(o.phone);

    if (!phone) {
      return res.status(400).json({
        error: 'Enter a valid Kenyan M-Pesa phone number.'
      });
    }

    if (o.total < 1 || o.total > 1000000) {
      return res.status(400).json({
        error: 'The payment amount must be between KSh 1 and KSh 1,000,000.'
      });
    }

    orderId = makeOrderId();
    const reference = makeZetuPayReference();

    const appUrl = getAppUrl();

    /*
      This return URL matches the HTML payment-return handler.
      Customer returns to the home page with order ID.
    */
    const redirectUrl =
      `${appUrl}/?payment=return&orderId=${encodeURIComponent(orderId)}`;

    // Save the order before starting payment.
    await pool.query(
      `INSERT INTO orders
       (id, customer, phone, email, location, seed_class,
        variety, potato_size, bags, delivery, notes,
        unit_price, total, payment_status,
        payment_phone, paystack_reference, zetupay_reference)
       VALUES
       ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
        'Pending verification',$14,$15,$16)`,
      [
        orderId,
        o.customer,
        o.phone,
        o.email,
        o.location,
        o.seedClass,
        o.variety,
        o.potatoSize,
        o.bags,
        o.delivery,
        o.notes,
        o.unitPrice,
        o.total,
        phone,
        reference,
        reference
      ]
    );

    // Initiate hosted checkout.
    const payment = await zetuPayRequest('/payment/initiate', {
      method: 'POST',
      body: JSON.stringify({
        amount: o.total,
        phoneNumber: phone,
        reference,
        redirectUrl,
        currency: 'KES',
        identifier: orderId
      })
    });

    if (!payment.checkoutUrl || !payment.paymentKey) {
      throw new Error('ZetuPay did not return a checkout link.');
    }

    // Store payment key for secure server-side verification.
    await pool.query(
      `UPDATE orders
       SET zetupay_payment_key = $2
       WHERE id = $1`,
      [orderId, payment.paymentKey]
    );

    return res.status(201).json({
      id: orderId,
      reference,
      paymentKey: payment.paymentKey,
      checkoutUrl: payment.checkoutUrl,
      total: o.total,
      unitPrice: o.unitPrice,
      paymentStatus: 'Pending verification',
      message: 'Order created. Continue to ZetuPay to complete payment.'
    });

  } catch (e) {
    console.error('ZETUPAY INITIATION ERROR:', e.message);

    return res.status(502).json({
      error: e.message || 'ZetuPay could not start payment.'
    });
  }
});

// ================================
// PAYMENT STATUS CHECK
// ================================

app.get('/api/orders/:id/payment', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, total,
              payment_status AS "paymentStatus",
              mpesa_receipt AS receipt,
              zetupay_payment_key AS "paymentKey"
       FROM orders
       WHERE id = $1`,
      [clean(req.params.id, 40)]
    );

    if (!r.rowCount) {
      return res.status(404).json({
        error: 'Order not found.'
      });
    }

    const order = r.rows[0];

    // Already verified: do not need to query provider again.
    if (order.paymentStatus === 'Verified') {
      return res.json({
        id: order.id,
        paymentStatus: 'Verified',
        receipt: order.receipt
      });
    }

    if (order.paymentKey) {
      try {
        const payment = await getZetuPayPayment(order.paymentKey);

        if (payment) {
          // Confirm successful payment against expected amount/currency.
          const verified = await verifyZetuPayPayment(
            order.paymentKey,
            order.total
          );

          if (verified) {
            await markZetuPayOrderPaid(
              order.paymentKey,
              verified
            );

            const updated = await pool.query(
              `SELECT payment_status AS "paymentStatus",
                      mpesa_receipt AS receipt
               FROM orders
               WHERE id = $1`,
              [order.id]
            );

            return res.json({
              id: order.id,
              ...updated.rows[0]
            });
          }

          // Mark a genuinely failed/cancelled/expired provider payment.
          await updateZetuPayFailedStatus(order.id, payment);

          if (
            ['failed', 'cancelled', 'canceled', 'expired']
              .includes(String(payment.status || '').toLowerCase())
          ) {
            return res.json({
              id: order.id,
              paymentStatus: 'Rejected',
              receipt: null
            });
          }
        }
      } catch (e) {
        console.error('ZetuPay status check error:', e.message);
      }
    }

    // Pending remains pending if provider verification is unavailable.
    const latest = await pool.query(
      `SELECT payment_status AS "paymentStatus",
              mpesa_receipt AS receipt
       FROM orders
       WHERE id = $1`,
      [order.id]
    );

    return res.json({
      id: order.id,
      ...latest.rows[0]
    });

  } catch (e) {
    console.error('Payment status endpoint error:', e.message);

    return res.status(500).json({
      error: 'Could not check payment status.'
    });
  }
});

// ================================
// CUSTOMER ORDER LOOKUP
// ================================

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
              variety,
              potato_size AS "potatoSize",
              bags, delivery, total,
              payment_status AS "paymentStatus",
              delivery_status AS "deliveryStatus",
              created_at AS created
       FROM orders
       WHERE regexp_replace(phone, '\\s', '', 'g') = $1
       ORDER BY created_at DESC
       LIMIT 30`,
      [phone]
    );

    return res.json(r.rows);

  } catch (e) {
    console.error('ORDER LOOKUP ERROR:', e.message);

    return res.status(500).json({
      error: 'Could not look up orders.'
    });
  }
});

// ================================
// ADMIN LOGIN
// ================================

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

  return res.json({
    token,
    expiresIn: 28800
  });
});

// ================================
// ADMIN ORDER LIST
// ================================

app.get('/api/admin/orders', auth, async (_req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, customer, phone, email, location,
              seed_class AS "seedClass",
              variety,
              potato_size AS "potatoSize",
              bags, delivery,
              mpesa_ref AS "mpesaRef",
              mpesa_receipt AS "mpesaReceipt",
              zetupay_reference AS "zetupayReference",
              zetupay_transaction_id AS "zetupayTransactionId",
              notes, unit_price AS "unitPrice", total,
              payment_status AS "paymentStatus",
              delivery_status AS "deliveryStatus",
              created_at AS created
       FROM orders
       ORDER BY created_at DESC
       LIMIT 500`
    );

    return res.json(r.rows);

  } catch (e) {
    console.error('ADMIN ORDER LIST ERROR:', e.message);

    return res.status(500).json({
      error: 'Could not load orders.'
    });
  }
});

// ================================
// ADMIN UPDATE ORDER STATUS
// ================================

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
      return res.status(404).json({
        error: 'Order not found.'
      });
    }

    return res.json({ ok: true });

  } catch (e) {
    console.error('ADMIN ORDER UPDATE ERROR:', e.message);

    return res.status(500).json({
      error: 'Could not update order.'
    });
  }
});

// ================================
// ADMIN PRODUCT UPDATE
// ================================

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

    return res.json(r.rows[0]);

  } catch (e) {
    console.error('ADMIN PRODUCT UPDATE ERROR:', e.message);

    return res.status(500).json({
      error: 'Could not update product.'
    });
  }
});

// ================================
// WEBSITE HOME PAGE
// ================================

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ================================
// START SERVER
// ================================

init()
  .then(() => {
    app.listen(process.env.PORT || 3000, '0.0.0.0', () => {
      console.log('Kisima app running with ZetuPay payments');
    });
  })
  .catch(e => {
    console.error('Database initialization failed:', e.message);
    process.exit(1);
  });
