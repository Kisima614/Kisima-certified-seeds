
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
    : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

// =================================
// POTATO SEED PRICES
// =================================

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

// =================================
// FERTILIZERS & CHEMICALS
// =================================

const SHOP_PRODUCTS = [
  {
    id: 'OCP',
    name: 'OCP',
    category: 'Fertilizer',
    unit: 'Bag',
    price: 2000,
    image: '/product-images/OCP'
  },
  {
    id: 'DAP',
    name: 'DAP',
    category: 'Fertilizer',
    unit: 'Bag',
    price: 4850,
    image: '/product-images/DAP'
  },
  {
    id: 'NPK',
    name: 'NPK',
    category: 'Fertilizer',
    unit: 'Bag',
    price: 2000,
    image: '/product-images/NPK'
  },
  {
    id: 'SUPERGRO',
    name: 'Supergro',
    category: 'Chemical',
    unit: '1 Litre',
    price: 2700,
    image: '/product-images/SUPERGRO'
  },
  {
    id: 'MISTRESS',
    name: 'Mistress',
    category: 'Chemical',
    unit: '1 kg',
    price: 800,
    image: '/product-images/MISTRESS'
  }
];

// =================================
// DATABASE INITIALIZATION
// =================================

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

    ALTER TABLE orders ADD COLUMN IF NOT EXISTS zetupay_payment_key TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS zetupay_transaction_id TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS zetupay_reference TEXT;

    CREATE TABLE IF NOT EXISTS shop_products (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      unit TEXT NOT NULL,
      price INTEGER NOT NULL CHECK(price >= 0),
      image TEXT NOT NULL DEFAULT '',
      available BOOLEAN NOT NULL DEFAULT true,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE shop_products
    ADD COLUMN IF NOT EXISTS image TEXT NOT NULL DEFAULT '';

    CREATE TABLE IF NOT EXISTS shop_orders (
      id TEXT PRIMARY KEY,
      customer TEXT NOT NULL,
      phone TEXT NOT NULL,
      email TEXT NOT NULL DEFAULT '',
      location TEXT NOT NULL,
      delivery TEXT NOT NULL,
      notes TEXT DEFAULT '',
      items JSONB NOT NULL DEFAULT '[]',
      total INTEGER NOT NULL,
      mpesa_ref TEXT DEFAULT '',
      payment_status TEXT NOT NULL DEFAULT 'Pending verification',
      delivery_status TEXT NOT NULL DEFAULT 'Order received',
      payment_phone TEXT,
      zetupay_payment_key TEXT,
      zetupay_reference TEXT,
      zetupay_transaction_id TEXT,
      mpesa_receipt TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS shop_orders_phone_idx
    ON shop_orders(phone);

    CREATE INDEX IF NOT EXISTS orders_phone_idx
    ON orders(phone);
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

  for (const product of SHOP_PRODUCTS) {
    await pool.query(
      `INSERT INTO shop_products
       (id, name, category, unit, price, image, available)
       VALUES($1,$2,$3,$4,$5,$6,true)
       ON CONFLICT(id) DO UPDATE
       SET name = EXCLUDED.name,
           category = EXCLUDED.category,
           unit = EXCLUDED.unit,
           price = EXCLUDED.price,
           image = EXCLUDED.image,
           updated_at = NOW()`,
      [
        product.id,
        product.name,
        product.category,
        product.unit,
        product.price,
        product.image
      ]
    );
  }

  console.log('Database initialized.');
}

const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);

// =================================
// AUTHENTICATION
// =================================

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

// =================================
// HELPERS
// =================================

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

// =================================
// ZETUPAY API
// =================================

async function zetuPayRequest(endpoint, options = {}) {
  const response = await fetch(
    `https://pay.zetupay.co.ke/api/v1${endpoint}`,
    {
      ...options,
      headers: {
        Authorization: `Bearer ${zetuPayKey()}`,
        'Content-Type': 'application/json',
        ...(options.headers || {})
      },
      signal: AbortSignal.timeout(20000)
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
      signal: AbortSignal.timeout(15000)
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok || data.success === false) {
    return null;
  }

  return data.data || data;
}

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

// =================================
// VERIFY SEED ZETUPAY PAYMENT
// =================================

async function markZetuPayOrderPaid(paymentKey, paymentData) {
  const result = await pool.query(
    `SELECT id, total, payment_status
     FROM orders
     WHERE zetupay_payment_key = $1`,
    [paymentKey]
  );

  if (!result.rowCount) {
    console.warn('Unknown seed ZetuPay payment key.');
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
    console.error('Seed ZetuPay payment verification failed.');
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

  console.log('Seed ZetuPay payment verified:', order.id);
}

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

// =================================
// VERIFY FARM SHOP ZETUPAY PAYMENT
// =================================

async function markShopOrderPaid(paymentKey, paymentData) {
  const result = await pool.query(
    `SELECT id, total, payment_status
     FROM shop_orders
     WHERE zetupay_payment_key = $1`,
    [paymentKey]
  );

  if (!result.rowCount) {
    console.warn('Unknown shop ZetuPay payment key.');
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
    console.error('Shop ZetuPay payment verification failed.');
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
    `UPDATE shop_orders
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

  console.log('Farm shop ZetuPay payment verified:', order.id);
}

async function updateShopZetuPayFailedStatus(orderId, payment) {
  const status = String(payment?.status || '').toLowerCase();

  if (!['failed', 'cancelled', 'canceled', 'expired'].includes(status)) {
    return false;
  }

  await pool.query(
    `UPDATE shop_orders
     SET payment_status = 'Rejected'
     WHERE id = $1
       AND payment_status <> 'Verified'`,
    [orderId]
  );

  return true;
}

// =================================
// PRODUCT IMAGE SERVING
// =================================

const productImageFiles = {
  OCP: 'images (1) (1).jpeg',
  DAP: 'images (30).jpeg',
  NPK: 'download (5).webp',
  SUPERGRO: 'download (1).webp',
  MISTRESS: 'download (3).webp'
};

app.get('/product-images/:product', (req, res) => {
  const filename = productImageFiles[req.params.product];

  if (!filename) {
    return res.status(404).send('Product image not found.');
  }

  res.sendFile(path.join(__dirname, filename), (err) => {
    if (err && !res.headersSent) {
      res.status(err.statusCode || 404).send('Image not found.');
    }
  });
});

// =================================
// STATIC WEBSITE
// =================================

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  etag: true
}));

// =================================
// HEALTH CHECK
// =================================

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false });
  }
});

// =================================
// SEED PRODUCTS
// =================================

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

// =================================
// FARM SHOP PRODUCT CATALOG
// =================================

app.get('/api/shop/products', async (_req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, name, category, unit, price, image, available
       FROM shop_products
       ORDER BY category, name`
    );

    res.json(r.rows);
  } catch (e) {
    console.error('SHOP PRODUCTS ERROR:', e.message);

    res.status(500).json({
      error: 'Could not load farm shop products.'
    });
  }
});

// =================================
// SEED ORDER VALIDATION
// =================================

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

// =================================
// FARM SHOP ORDER VALIDATION
// =================================

async function getShopOrderDetails(b) {
  const customer = clean(b.customer, 100);
  const phone = clean(b.phone, 40);
  const email = clean(b.email, 200).toLowerCase();
  const location = clean(b.location, 220);
  const delivery = clean(b.delivery, 100);
  const notes = clean(b.notes, 500);

  if (
    !customer ||
    !phone ||
    !location ||
    !delivery ||
    (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
  ) {
    throw new Error('Please complete the required customer information.');
  }

  if (!['Delivery', 'Collection'].includes(delivery)) {
    throw new Error('Please select Delivery or Collection.');
  }

  if (!Array.isArray(b.items) || b.items.length < 1 || b.items.length > 50) {
    throw new Error('Your cart must contain at least one item.');
  }

  const items = [];
  let total = 0;

  for (const item of b.items) {
    const quantity = Number(item.quantity);

    if (
      !Number.isInteger(quantity) ||
      quantity < 1 ||
      quantity > 500
    ) {
      throw new Error('Invalid product quantity.');
    }

    if (item.type === 'seed') {
      const variety = clean(item.variety, 100);
      const seedClass = clean(item.seedClass, 50);
      const potatoSize = clean(item.potatoSize, 20);

      if (!variety || !CLASS_PRICES[seedClass]) {
        throw new Error('Invalid potato seed item.');
      }

      if (!['Size 1', 'Size 2'].includes(potatoSize)) {
        throw new Error('Invalid potato size.');
      }

      const seedProduct = await pool.query(
        `SELECT name, available
         FROM products
         WHERE name = $1`,
        [variety]
      );

      if (!seedProduct.rowCount || !seedProduct.rows[0].available) {
        throw new Error(`${variety} is currently unavailable.`);
      }

      const unitPrice = CLASS_PRICES[seedClass];
      const lineTotal = unitPrice * quantity;

      items.push({
        type: 'seed',
        id: variety,
        name: variety,
        category: 'Certified Potato Seeds',
        unit: '50kg Bag',
        seedClass,
        potatoSize,
        quantity,
        unitPrice,
        lineTotal
      });

      total += lineTotal;
      continue;
    }

    if (item.type === 'product') {
      const productId = clean(item.productId, 50);

      const productResult = await pool.query(
        `SELECT id, name, category, unit, price, available
         FROM shop_products
         WHERE id = $1`,
        [productId]
      );

      if (
        !productResult.rowCount ||
        !productResult.rows[0].available
      ) {
        throw new Error('One of the farm shop products is unavailable.');
      }

      const product = productResult.rows[0];
      const lineTotal = Number(product.price) * quantity;

      items.push({
        type: 'product',
        id: product.id,
        name: product.name,
        category: product.category,
        unit: product.unit,
        quantity,
        unitPrice: Number(product.price),
        lineTotal
      });

      total += lineTotal;
      continue;
    }

    throw new Error('Invalid item type in your cart.');
  }

  if (!Number.isSafeInteger(total) || total < 1 || total > 1000000) {
    throw new Error('Invalid order total.');
  }

  return {
    customer,
    phone,
    email,
    location,
    delivery,
    notes,
    items,
    total
  };
}

// =================================
// SEED ZETUPAY CHECKOUT
// =================================

app.post('/api/orders/zetupay', async (req, res) => {
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

    const orderId = makeOrderId();
    const reference = makeZetuPayReference();
    const appUrl = getAppUrl();

    const redirectUrl =
      `${appUrl}/?payment=return&orderId=${encodeURIComponent(orderId)}`;

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

// =================================
// FARM SHOP ZETUPAY CHECKOUT
// =================================

app.post('/api/shop/orders/zetupay', async (req, res) => {
  try {
    const o = await getShopOrderDetails(req.body || {});
    const phone = normalizeKenyanPhone(o.phone);

    if (!phone) {
      return res.status(400).json({
        error: 'Enter a valid Kenyan M-Pesa phone number.'
      });
    }

    if (o.total < 1 || o.total > 1000000) {
      return res.status(400).json({
        error: 'Payment must be between KSh 1 and KSh 1,000,000.'
      });
    }

    const orderId = makeOrderId();
    const reference = makeZetuPayReference();
    const appUrl = getAppUrl();

    const redirectUrl =
      `${appUrl}/?shopPayment=return&orderId=${encodeURIComponent(orderId)}`;

    await pool.query(
      `INSERT INTO shop_orders
       (id, customer, phone, email, location, delivery,
        notes, items, total, payment_status,
        payment_phone, zetupay_reference)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,
              'Pending verification',$10,$11)`,
      [
        orderId,
        o.customer,
        o.phone,
        o.email,
        o.location,
        o.delivery,
        o.notes,
        JSON.stringify(o.items),
        o.total,
        phone,
        reference
      ]
    );

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

    await pool.query(
      `UPDATE shop_orders
       SET zetupay_payment_key = $2
       WHERE id = $1`,
      [orderId, payment.paymentKey]
    );

    return res.status(201).json({
      id: orderId,
      reference,
      paymentKey: payment.paymentKey,
      checkoutUrl: payment.checkoutUrl,
      items: o.items,
      total: o.total,
      paymentStatus: 'Pending verification',
      message: 'Farm shop order created. Continue to ZetuPay.'
    });

  } catch (e) {
    console.error('SHOP ZETUPAY ERROR:', e.message);

    return res.status(502).json({
      error: e.message || 'ZetuPay could not start payment.'
    });
  }
});

// =================================
// SEED PAYMENT STATUS CHECK
// =================================

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
        console.error('Seed payment status error:', e.message);
      }
    }

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
    console.error('SEED PAYMENT STATUS ERROR:', e.message);

    return res.status(500).json({
      error: 'Could not check payment status.'
    });
  }
});

// =================================
// FARM SHOP PAYMENT STATUS
// =================================

app.get('/api/shop/orders/:id/payment', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, total,
              payment_status AS "paymentStatus",
              mpesa_receipt AS receipt,
              zetupay_payment_key AS "paymentKey"
       FROM shop_orders
       WHERE id = $1`,
      [clean(req.params.id, 40)]
    );

    if (!r.rowCount) {
      return res.status(404).json({
        error: 'Shop order not found.'
      });
    }

    const order = r.rows[0];

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
          const verified = await verifyZetuPayPayment(
            order.paymentKey,
            order.total
          );

          if (verified) {
            await markShopOrderPaid(
              order.paymentKey,
              verified
            );

            const updated = await pool.query(
              `SELECT payment_status AS "paymentStatus",
                      mpesa_receipt AS receipt
               FROM shop_orders
               WHERE id = $1`,
              [order.id]
            );

            return res.json({
              id: order.id,
              ...updated.rows[0]
            });
          }

          await updateShopZetuPayFailedStatus(order.id, payment);

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
        console.error('Shop payment status error:', e.message);
      }
    }

    const latest = await pool.query(
      `SELECT payment_status AS "paymentStatus",
              mpesa_receipt AS receipt
       FROM shop_orders
       WHERE id = $1`,
      [order.id]
    );

    return res.json({
      id: order.id,
      ...latest.rows[0]
    });

  } catch (e) {
    console.error('SHOP PAYMENT STATUS ERROR:', e.message);

    return res.status(500).json({
      error: 'Could not check farm shop payment status.'
    });
  }
});

// =================================
// CUSTOMER SEED ORDER LOOKUP
// =================================

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

// =================================
// CUSTOMER FARM SHOP LOOKUP
// =================================

app.post('/api/shop/orders/lookup', async (req, res) => {
  const phone = clean(req.body?.phone, 40).replace(/\s/g, '');

  if (phone.length < 7) {
    return res.status(400).json({
      error: 'Enter the phone number used for the order.'
    });
  }

  try {
    const r = await pool.query(
      `SELECT id, customer, location, delivery,
              items, total,
              payment_status AS "paymentStatus",
              delivery_status AS "deliveryStatus",
              created_at AS created
       FROM shop_orders
       WHERE regexp_replace(phone, '\\s', '', 'g') = $1
       ORDER BY created_at DESC
       LIMIT 30`,
      [phone]
    );

    return res.json(r.rows);

  } catch (e) {
    console.error('SHOP ORDER LOOKUP ERROR:', e.message);

    return res.status(500).json({
      error: 'Could not look up farm shop orders.'
    });
  }
});

// =================================
// ADMIN LOGIN
// =================================

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

// =================================
// ADMIN SEED ORDER LIST
// =================================

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

// =================================
// ADMIN FARM SHOP ORDERS
// =================================

app.get('/api/admin/shop-orders', auth, async (_req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, customer, phone, email, location,
              delivery, notes, items, total,
              mpesa_ref AS "mpesaRef",
              mpesa_receipt AS "mpesaReceipt",
              zetupay_reference AS "zetupayReference",
              zetupay_transaction_id AS "zetupayTransactionId",
              payment_status AS "paymentStatus",
              delivery_status AS "deliveryStatus",
              created_at AS created
       FROM shop_orders
       ORDER BY created_at DESC
       LIMIT 500`
    );

    return res.json(r.rows);

  } catch (e) {
    console.error('ADMIN SHOP ORDER LIST ERROR:', e.message);

    return res.status(500).json({
      error: 'Could not load farm shop orders.'
    });
  }
});

// =================================
// ADMIN UPDATE SEED ORDER STATUS
// =================================

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
       SET payment_status = COALESCE($1, payment_status),
           delivery_status = COALESCE($2, delivery_status)
       WHERE id = $3
       RETURNING id`,
      [pay, del, req.params.id]
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

// =================================
// ADMIN UPDATE FARM SHOP ORDER
// =================================

app.patch('/api/admin/shop-orders/:id', auth, async (req, res) => {
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
      `UPDATE shop_orders
       SET payment_status = COALESCE($1, payment_status),
           delivery_status = COALESCE($2, delivery_status)
       WHERE id = $3
       RETURNING id`,
      [pay, del, req.params.id]
    );

    if (!r.rowCount) {
      return res.status(404).json({
        error: 'Shop order not found.'
      });
    }

    return res.json({ ok: true });

  } catch (e) {
    console.error('ADMIN SHOP ORDER UPDATE ERROR:', e.message);

    return res.status(500).json({
      error: 'Could not update farm shop order.'
    });
  }
});

// =================================
// ADMIN UPDATE SEED PRODUCT
// =================================

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

// =================================
// ADMIN UPDATE FARM SHOP PRODUCT
// =================================

app.patch('/api/admin/shop-products/:id', auth, async (req, res) => {
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
      `UPDATE shop_products
       SET price = $2,
           available = $3,
           updated_at = NOW()
       WHERE id = $1
       RETURNING id, name, category, unit, price, available`,
      [req.params.id, price, available]
    );

    if (!r.rowCount) {
      return res.status(404).json({
        error: 'Shop product not found.'
      });
    }

    return res.json(r.rows[0]);

  } catch (e) {
    console.error('ADMIN SHOP PRODUCT UPDATE ERROR:', e.message);

    return res.status(500).json({
      error: 'Could not update farm shop product.'
    });
  }
});

// =================================
// WEBSITE HOME PAGE
// =================================

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// =================================
// START SERVER
// =================================

async function startServer() {
  try {
    await init();

    const PORT = Number(process.env.PORT) || 3000;

    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`Kisima app running on port ${PORT}`);
      console.log('ZetuPay and Farm Shop enabled.');
    });

    server.on('error', (error) => {
      console.error('SERVER START ERROR:', error.message);
      process.exit(1);
    });

    process.on('SIGTERM', () => {
      console.log('SIGTERM received. Closing server.');

      server.close(async () => {
        await pool.end();
        process.exit(0);
      });
    });

  } catch (e) {
    console.error('Database initialization failed:', e.message);
    process.exit(1);
  }
}

startServer();
