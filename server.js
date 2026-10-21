const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const required = ['DATABASE_URL', 'ADMIN_PASSWORD', 'JWT_SECRET'];
for (const k of required) if (!process.env[k]) {
  console.error(`Missing required environment variable: ${k}`);
  process.exit(1);
}
if (process.env.NODE_ENV === 'production' && process.env.ADMIN_PASSWORD.length < 14) {
  console.error('ADMIN_PASSWORD must be at least 14 characters in production.');
  process.exit(1);
}
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '40kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false }
});
const seed = [
  ['Unica Size 1',3750,true],['Unica Size 2',3450,true],['Shangi',3750,true],
  ['Super Shangi',3750,true],['Dutch',3750,true],['Wanjiku',3750,true],
  ['Stephen',3750,false],['Sheherekea',3750,false]
];
async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, price INTEGER NOT NULL CHECK(price >= 0),
      available BOOLEAN NOT NULL DEFAULT true, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY, customer TEXT NOT NULL, phone TEXT NOT NULL, location TEXT NOT NULL,
      seed_class TEXT NOT NULL, variety TEXT NOT NULL, bags INTEGER NOT NULL CHECK(bags BETWEEN 1 AND 500),
      delivery TEXT NOT NULL, mpesa_ref TEXT NOT NULL, notes TEXT DEFAULT '',
      unit_price INTEGER NOT NULL, total INTEGER NOT NULL, payment_status TEXT NOT NULL DEFAULT 'Pending verification',
      delivery_status TEXT NOT NULL DEFAULT 'Order received', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  for (const [name,price,available] of seed) {
    await pool.query('INSERT INTO products(name,price,available) VALUES($1,$2,$3) ON CONFLICT(name) DO NOTHING',[name,price,available]);
  }
}
const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
function auth(req,res,next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i,'');
  try {
    const data = jwt.verify(token, process.env.JWT_SECRET);
    if (data.role !== 'admin') throw new Error('role');
    req.admin = true; next();
  } catch { return res.status(401).json({error:'Please sign in as administrator.'}); }
}
const clean = (v,max=200) => String(v ?? '').trim().slice(0,max);
app.get('/api/health', async (_req,res) => {
  try { await pool.query('SELECT 1'); res.json({ok:true}); }
  catch { res.status(503).json({ok:false}); }
});
app.get('/api/products', async (_req,res) => {
  try { const r=await pool.query('SELECT id,name,price,available FROM products ORDER BY id'); res.json(r.rows); }
  catch { res.status(500).json({error:'Could not load products.'}); }
});
app.post('/api/orders', async (req,res) => {
  const b=req.body || {};
  const customer=clean(b.customer,100), phone=clean(b.phone,40), location=clean(b.location,220);
  const variety=clean(b.variety,100), seedClass=clean(b.seedClass,50), delivery=clean(b.delivery,100);
  const mpesa=clean(b.mpesaRef,40).toUpperCase(), notes=clean(b.notes,500);
  const bags=Number(b.bags);
  if (!customer || !phone || !location || !variety || !seedClass || !delivery || !mpesa || !Number.isInteger(bags) || bags<1 || bags>500)
    return res.status(400).json({error:'Please complete all required fields with a valid bag quantity.'});
  if (!/^[A-Z0-9]{8,15}$/.test(mpesa)) return res.status(400).json({error:'Check the M-Pesa transaction reference format.'});
  try {
    const pr=await pool.query('SELECT name,price,available FROM products WHERE name=$1',[variety]);
    if (!pr.rowCount || !pr.rows[0].available) return res.status(400).json({error:'This variety is not currently available to order. Please contact Kisima.'});
    const p=pr.rows[0], id='KS'+Date.now().toString().slice(-8)+Math.random().toString(36).slice(2,5).toUpperCase();
    const total=p.price*bags;
    await pool.query(`INSERT INTO orders(id,customer,phone,location,seed_class,variety,bags,delivery,mpesa_ref,notes,unit_price,total)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [id,customer,phone,location,seedClass,variety,bags,delivery,mpesa,notes,p.price,total]);
    res.status(201).json({id,total,unitPrice:p.price,paymentStatus:'Pending verification',message:'Order received. Payment is pending manual verification.'});
  } catch { res.status(500).json({error:'Could not save order. Please try again or contact Kisima.'}); }
});
app.post('/api/orders/lookup', async (req,res) => {
  const phone=clean(req.body?.phone,40).replace(/\s/g,'');
  if(phone.length<7) return res.status(400).json({error:'Enter the phone number used for the order.'});
  try {
    const r=await pool.query(`SELECT id,customer,location,seed_class AS "seedClass",variety,bags,delivery,total,
      payment_status AS "paymentStatus",delivery_status AS "deliveryStatus",created_at AS created
      FROM orders WHERE regexp_replace(phone,'\\s','','g')=$1 ORDER BY created_at DESC LIMIT 30`,[phone]);
    res.json(r.rows);
  } catch { res.status(500).json({error:'Could not look up orders.'}); }
});
app.post('/api/admin/login', async (req,res) => {
  const password=String(req.body?.password || '');
  if(password.length>200 || !await bcrypt.compare(password,adminHash)) return res.status(401).json({error:'Invalid administrator password.'});
  const token=jwt.sign({role:'admin'},process.env.JWT_SECRET,{expiresIn:'8h'});
  res.json({token,expiresIn:28800});
});
app.get('/api/admin/orders',auth,async (_req,res) => {
  try { const r=await pool.query(`SELECT id,customer,phone,location,seed_class AS "seedClass",variety,bags,delivery,
    mpesa_ref AS "mpesaRef",notes,unit_price AS "unitPrice",total,payment_status AS "paymentStatus",
    delivery_status AS "deliveryStatus",created_at AS created FROM orders ORDER BY created_at DESC LIMIT 500`); res.json(r.rows); }
  catch { res.status(500).json({error:'Could not load orders.'}); }
});
app.patch('/api/admin/orders/:id',auth,async (req,res) => {
  const pay=['Pending verification','Verified','Rejected'].includes(req.body?.paymentStatus)?req.body.paymentStatus:null;
  const del=['Order received','Preparing','Dispatched','Delivered'].includes(req.body?.deliveryStatus)?req.body.deliveryStatus:null;
  if(!pay && !del) return res.status(400).json({error:'No valid status supplied.'});
  try {
    const r=await pool.query(`UPDATE orders SET payment_status=COALESCE($2,payment_status),
      delivery_status=COALESCE($3,delivery_status) WHERE id=$1 RETURNING id`,[req.params.id,pay,del]);
    if(!r.rowCount)return res.status(404).json({error:'Order not found.'});
    res.json({ok:true});
  } catch { res.status(500).json({error:'Could not update order.'}); }
});
app.patch('/api/admin/products/:id',auth,async (req,res) => {
  const price=Number(req.body?.price), available=req.body?.available;
  if(!Number.isInteger(price)||price<0||price>10000000||typeof available!=='boolean')return res.status(400).json({error:'Invalid price or availability.'});
  try { const r=await pool.query('UPDATE products SET price=$2,available=$3,updated_at=NOW() WHERE id=$1 RETURNING id,name,price,available',[req.params.id,price,available]); if(!r.rowCount)return res.status(404).json({error:'Product not found.'}); res.json(r.rows[0]); }
  catch { res.status(500).json({error:'Could not update product.'}); }
});
app.get('*',(_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
init().then(()=>app.listen(process.env.PORT||3000,'0.0.0.0',()=>console.log('Kisima app running'))).catch(e=>{console.error('Database initialization failed',e.message);process.exit(1);});
