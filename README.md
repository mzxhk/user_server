# Auth API

This service is the only component that connects to MySQL. It reads the connection settings and table name from `server/mysql.txt`, creates `User_Info` when it does not exist, and stores passwords as bcrypt hashes.

Run it from this directory:

```powershell
npm install
$env:MYSQL_SSL_REJECT_UNAUTHORIZED='true'
npm start
```

Set `JWT_SECRET` to a long random value outside local development. The API returns an 8-hour bearer token after login and requires it for `PATCH /api/me`, so users can update only their own profile.

The API loads the project-root `ca.pem` certificate into the Node MySQL TLS connection and requires certificate verification. Keep `MYSQL_SSL_REJECT_UNAUTHORIZED=true`; do not disable verification in production.

The Flutter app uses `http://localhost:3000/api` by default. For an Android emulator, use the host machine address (often `http://10.0.2.2:3000/api`); for a physical device or another computer, use the API machine's LAN address:

```powershell
flutter run -d chrome --dart-define=API_BASE_URL=http://localhost:3000/api
flutter run -d windows --dart-define=API_BASE_URL=http://localhost:3000/api
flutter run -d android --dart-define=API_BASE_URL=http://10.0.2.2:3000/api
```

The existing table must have these columns if it already exists: `id`, `name`, `email`, `password_hash`, and `created_at`. The provided hostname is used exactly as written in `server/mysql.txt`.
