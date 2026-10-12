# FixNow local prototype — role-based authentication

This version adds customer email/password accounts, private administrator account creation, session tokens, and server-side role/booking ownership checks. It preserves the React/Vite frontend, FastAPI backend, SQLite database, sample mechanics, booking workflow, and browser GPS capture.

## Requirements
- Python 3.11+ (Python 3.14 may work with current FastAPI/Pydantic releases)
- Node.js and npm
- VS Code

## 1. Start the backend (Terminal 1)
From the project root `FixNow`:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If `.venv` already exists, do not recreate it; activate it and install the requirements.

Create the first private administrator account:

```powershell
python -m app.create_admin
```

Enter the administrator email and a unique password of at least 12 characters when prompted. The password is hidden while typing. The script does not print or store the password in plain text. Run this command from the `backend` folder with the virtual environment activated. If the admin already exists, the script makes no changes.

Start the API:

```powershell
python -m uvicorn app.main:app --reload
```

Keep this terminal open. Check `http://127.0.0.1:8000/api/health` and `http://127.0.0.1:8000/docs`.

## 2. Start the frontend (Terminal 2)
Open a second VS Code terminal:

```powershell
cd "C:\path\to\FixNow\frontend"
npm install
npm run dev
```

Use the actual folder path on your computer. Open the local URL printed by Vite, normally `http://localhost:5173/`. The Vite development proxy forwards `/api` requests to the backend at `http://127.0.0.1:8000`.

## 3. Test customer authentication
1. Click **Register**.
2. Create a customer account using an email and a password of at least 10 characters.
3. Confirm you land on the homepage as a signed-in customer.
4. Click **Request help**, submit a demo request, and open **My booking**.
5. Sign out and sign back in. Your booking should still be associated with that account.
6. Register/sign in with a second customer and confirm the first customer's bookings are not returned.

## 4. Test administrator access
1. Sign out of the customer account.
2. Sign in using the admin email and password created with `python -m app.create_admin`.
3. The Admin and Mechanic desk navigation items should appear.
4. Confirm the admin can see all bookings, assign sample mechanics, and update statuses.
5. Sign back in as a customer and verify admin endpoints are forbidden (HTTP 403).

## API security behaviour
- Registration always creates a `customer`; clients cannot self-select the admin role.
- Passwords are stored as PBKDF2-HMAC-SHA256 salted hashes.
- Login issues a random bearer session token; only its SHA-256 hash is stored in SQLite. Sessions expire after 7 days and logout revokes the current session.
- Booking list/detail endpoints require login. Customers only see their own bookings; admin can see all bookings.
- Only admin can update booking status, assign mechanics, or read `/api/admin/summary`.
- Customers can cancel their own booking while its status is `Requested` or `Searching`.
- Mechanic login is intentionally deferred. The mechanic desk is admin-only for now.

## Existing database
The API migrates an existing `bookings` table by adding a nullable `user_id` column if missing. Existing historical bookings have no owner and remain visible to administrators only; they are not automatically assigned to a customer. The existing SQLite file is not deleted.

## GPS and prototype limitations
GPS remains browser-permission-based and optional. Use `localhost` during development; deployed browser geolocation requires HTTPS. This is not live mechanic GPS tracking or production dispatch. Sample mechanics and ETAs are illustrative. Before public deployment, add HTTPS, stronger operational controls/rate limiting, password reset, privacy/data-retention decisions, and security review.
