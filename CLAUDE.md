# Alyan Space Backend

## Structure
```
src/
├── config/          # Auth, database, logger
├── controllers/     # authController.js
├── middleware/      # auth.js, rateLimiter.js, cors.js, errorHandler.js
├── models/          # User.js
├── routes/          # auth.js, index.js
├── services/        # authService.js
├── utils/           # jwt.js, validation.js
└── app.js
```

## Environment (.env)
```
ADMIN_EMAIL=admin@alyanspace.com
ADMIN_PASSWORD=AlyanSpace2024!
JWT_SECRET=your-secret-key
JWT_REFRESH_SECRET=your-refresh-secret
MONGODB_URI=your-mongodb-connection
```

## Commands
```bash
npm run dev    # Start development server
```

## API Routes
**Public:**
- `POST /api/auth/login` - Login with email/password
- `POST /api/auth/refresh` - Refresh token

**Protected:**
- `POST /api/auth/logout` - Logout
- `GET /api/auth/profile` - Get user profile

## Key Features
- Single admin user system
- JWT tokens (15min access + 7day refresh)
- bcrypt password hashing
- HTTP-only cookies for refresh tokens
- Rate limiting (disabled in development)
- MongoDB with Mongoose