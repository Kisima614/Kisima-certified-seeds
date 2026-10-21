# Kisima Certified Seeds — Online App

This is a deployable web app/PWA starter for Kisima Certified Seeds. Customers can open the site from their own phones, place orders, enter M-Pesa transaction references, and check their order status. The administrator can sign in to manage prices/availability, verify payment references manually, and update delivery status.

## Important status and limits

- This is the online app source code, not a live hosted URL or a compiled Android APK.
- To make it live, an owner must connect a PostgreSQL database and deploy the app using their own hosting account.
- M-Pesa transaction references are **not automatically verified**. Admin must check the actual payment in M-Pesa and then mark it verified. Never treat a customer-entered code as proof of payment.
- The app does not store full M-Pesa PINs or credentials and does not initiate payments.
- Set a strong `ADMIN_PASSWORD` and keep the database URL and `JWT_SECRET` private.
- For production payment automation, integrate Safaricom Daraja STK Push and payment callbacks after obtaining approved credentials and testing in sandbox.

## Deploy (no coding required after setup)

1. Create a PostgreSQL database with a provider such as Neon or Supabase. Copy its connection string. Ensure external connections are allowed and use SSL.
2. Create a GitHub repository and upload the contents of this folder.
3. In Render, create a **New Web Service** from that repository. Render can use `render.yaml`; otherwise set:
   - Build command: `npm install`
   - Start command: `npm start`
4. Add environment variables:
   - `DATABASE_URL`: your PostgreSQL connection string
   - `DATABASE_SSL`: `true`
   - `ADMIN_PASSWORD`: a long, unique password
   - `JWT_SECRET`: a long random secret (at least 32 characters)
   - `NODE_ENV`: `production`
5. Deploy. Render gives you a public HTTPS URL. Open it on Android Chrome and choose **Add to Home screen** to use it like an app.
6. Sign in via **Admin**. Add or correct varieties, prices and availability before accepting live orders.

## Default seed prices included (review before going live)

- Unica Size 1 — KSh 3,750 / 50 kg bag
- Unica Size 2 — KSh 3,450 / 50 kg bag
- Other listed varieties currently use KSh 3,750 / 50 kg bag as a draft price; confirm each price and availability in Admin before launch.
- Basic generation and Prebasic pricing should be confirmed in Admin before enabling those classes.

## Local testing

Requires Node.js 20+ and PostgreSQL. Set environment variables (see `.env.example`), then run:

```sh
npm install
npm start
```

Open `http://localhost:3000`.

## Privacy and operations

This app collects names, phone numbers, delivery locations, order details, and M-Pesa transaction references. Publish a privacy notice, restrict staff access, retain records only as needed, and arrange backups before using it commercially.
