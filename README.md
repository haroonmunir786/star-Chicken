# Star Chicken Cloud Invoice App

This package converts the existing `palmcity.html` invoice app from browser-only storage to a Node.js + Express + Supabase PostgreSQL backend.

## Architecture

Browser -> Express backend -> Supabase PostgreSQL

The backend also serves `palmcity.html`, so there is no CORS configuration required.

## 1. Install Node.js

Install the current LTS version from:
https://nodejs.org/en/download/

Express 5 requires Node.js 18 or newer.

## 2. Create Supabase project

1. Create a Supabase account/project.
2. Open SQL Editor.
3. Paste all of `schema.sql`.
4. Run it.
5. Go to database connection settings and copy a PostgreSQL connection string.
6. Put it in `.env` as `DATABASE_URL`.

For a backend running on IPv4, Supabase documents the pooler/session connection as an option.

## 3. Configure .env

Copy `.env.example` to `.env`.

Set:
- DATABASE_URL
- JWT_SECRET (long random value)
- APP_PASSWORD (your invoice app password)

Never upload `.env` to GitHub.

## 4. Install dependencies

Open Command Prompt in this folder:

npm install

## 5. Start

npm start

Then open:

http://localhost:3000

## 6. Login

Use the APP_PASSWORD from `.env`.

## 7. Existing local invoices

Your old browser data is still kept in IndexedDB.

After logging in:
Share / Print -> Sync Old Local Data

This uploads the old invoices to PostgreSQL. The migration is based on invoice IDs, so running it again updates the same IDs rather than creating duplicate rows.

## 8. Important

The old app has Google Sheets code as well. This cloud version does not remove it. The database becomes the primary invoice store. Google Sheets can be kept as a reporting/export destination.

## 9. Production deployment

A Render Web Service can run Node/Express. Set the same environment variables in the Render dashboard and use:

Build command:
npm install

Start command:
npm start

The service must listen on process.env.PORT, which this app does.

Free Render web services can spin down after 15 minutes of inactivity, so the first request after idle can take about a minute. Free services are better treated as testing/hobby infrastructure, not guaranteed production infrastructure.

Supabase Free has a 500 MB database-size quota before the project becomes read-only, so monitor usage.

## 10. Future improvements

Recommended next:
- Proper user accounts/roles
- Audit log
- Customer master table
- Product master table
- Server-side invoice numbering
- Daily/monthly sales reports
- Google Sheets automatic reporting
- Automatic database backups
