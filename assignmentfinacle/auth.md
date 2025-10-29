# Authentication & Authorization with JWT Implementation

## Complete TypeScript + Node.js Implementation Guide

---

## Table of Contents
1. [Project Setup](#project-setup)
2. [Environment Configuration](#environment-configuration)
3. [Type Definitions](#type-definitions)
4. [Utilities](#utilities)
5. [Models](#models)
6. [Services](#services)
7. [Controllers](#controllers)
8. [Middleware](#middleware)
9. [Routes](#routes)
10. [Application Entry](#application-entry)
11. [Testing](#testing)

---

## Project Setup

### 1. Initialize Project

```bash
mkdir jwt-auth-api
cd jwt-auth-api
npm init -y
```

### 2. Install Dependencies

```bash
# Production dependencies
npm install express bcrypt jsonwebtoken dotenv

# Development dependencies
npm install -D typescript @types/node @types/express @types/bcrypt @types/jsonwebtoken ts-node nodemon

# Optional: for validation
npm install express-validator
```

### 3. package.json

```json
{
  "name": "jwt-auth-api",
  "version": "1.0.0",
  "description": "Authentication API with JWT",
  "main": "dist/app.js",
  "scripts": {
    "start": "node dist/app.js",
    "dev": "nodemon --exec ts-node src/app.ts",
    "build": "tsc",
    "watch": "tsc -w"
  },
  "keywords": ["jwt", "authentication", "typescript"],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "express": "^4.18.2",
    "bcrypt": "^5.1.1",
    "jsonwebtoken": "^9.0.2",
    "dotenv": "^16.3.1"
  },
  "devDependencies": {
    "typescript": "^5.2.2",
    "@types/node": "^20.8.0",
    "@types/express": "^4.17.20",
    "@types/bcrypt": "^5.0.1",
    "@types/jsonwebtoken": "^9.0.4",
    "ts-node": "^10.9.1",
    "nodemon": "^3.0.1"
  }
}
```

### 4. tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "moduleResolution": "node",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

---

## Environment Configuration

### .env

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# JWT Configuration
JWT_ACCESS_SECRET=your_access_token_secret_key_here_change_in_production
JWT_REFRESH_SECRET=your_refresh_token_secret_key_here_change_in_production
JWT_ACCESS_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d

# Bcrypt Configuration
BCRYPT_SALT_ROUNDS=10
```

### src/config/environment.ts

```typescript
import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

interface Config {
  port: number;
  nodeEnv: string;
  jwt: {
    accessSecret: string;
    refreshSecret: string;
    accessExpiration: string;
    refreshExpiration: string;
  };
  bcrypt: {
    saltRounds: number;
  };
}

const config: Config = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET || 'default_access_secret',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'default_refresh_secret',
    accessExpiration: process.env.JWT_ACCESS_EXPIRATION || '15m',
    refreshExpiration: process.env.JWT_REFRESH_EXPIRATION || '7d',
  },
  bcrypt: {
    saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10),
  },
};

// Validate critical configuration
if (config.jwt.accessSecret === 'default_access_secret' || 
    config.jwt.refreshSecret === 'default_refresh_secret') {
  console.warn('⚠️  WARNING: Using default JWT secrets. Please set JWT_ACCESS_SECRET and JWT_REFRESH_SECRET in .env file');
}

export default config;
```

---

## Type Definitions

### src/types/index.ts

```typescript
import { Request } from 'express';

export interface SignupDto {
  login: string;
  password: string;
}

export interface LoginDto {
  login: string;
  password: string;
}

export interface RefreshTokenDto {
  refreshToken: string;
}

export interface User {
  id: string;
  login: string;
  passwordHash: string;
  createdAt: Date;
}

export interface JwtPayload {
  userId: string;
  login: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface AuthRequest extends Request {
  user?: JwtPayload;
}

export interface ApiError {
  message: string;
  statusCode: number;
}
```

---

## Utilities

### src/utils/password.util.ts

```typescript
import bcrypt from 'bcrypt';
import config from '../config/environment';

export class PasswordUtil {
  /**
   * Hash a plain text password
   * @param password - Plain text password
   * @returns Hashed password
   */
  static async hashPassword(password: string): Promise<string> {
    const saltRounds = config.bcrypt.saltRounds;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
  }

  /**
   * Compare plain text password with hashed password
   * @param password - Plain text password
   * @param hashedPassword - Hashed password from database
   * @returns True if passwords match
   */
  static async comparePassword(
    password: string,
    hashedPassword: string
  ): Promise<boolean> {
    return await bcrypt.compare(password, hashedPassword);
  }
}
```

### src/utils/jwt.util.ts

```typescript
import jwt from 'jsonwebtoken';
import config from '../config/environment';
import { JwtPayload, TokenPair } from '../types';

export class JwtUtil {
  /**
   * Generate access token
   * @param payload - User data to encode in token
   * @returns Access token string
   */
  static generateAccessToken(payload: JwtPayload): string {
    return jwt.sign(payload, config.jwt.accessSecret, {
      expiresIn: config.jwt.accessExpiration,
    });
  }

  /**
   * Generate refresh token
   * @param payload - User data to encode in token
   * @returns Refresh token string
   */
  static generateRefreshToken(payload: JwtPayload): string {
    return jwt.sign(payload, config.jwt.refreshSecret, {
      expiresIn: config.jwt.refreshExpiration,
    });
  }

  /**
   * Generate both access and refresh tokens
   * @param payload - User data to encode in tokens
   * @returns Token pair object
   */
  static generateTokenPair(payload: JwtPayload): TokenPair {
    return {
      accessToken: this.generateAccessToken(payload),
      refreshToken: this.generateRefreshToken(payload),
    };
  }

  /**
   * Verify access token
   * @param token - Access token to verify
   * @returns Decoded payload if valid
   * @throws Error if token is invalid or expired
   */
  static verifyAccessToken(token: string): JwtPayload {
    try {
      const decoded = jwt.verify(token, config.jwt.accessSecret) as JwtPayload;
      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Access token has expired');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid access token');
      }
      throw new Error('Token verification failed');
    }
  }

  /**
   * Verify refresh token
   * @param token - Refresh token to verify
   * @returns Decoded payload if valid
   * @throws Error if token is invalid or expired
   */
  static verifyRefreshToken(token: string): JwtPayload {
    try {
      const decoded = jwt.verify(token, config.jwt.refreshSecret) as JwtPayload;
      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Refresh token has expired');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid refresh token');
      }
      throw new Error('Token verification failed');
    }
  }

  /**
   * Extract token from Bearer authorization header
   * @param authHeader - Authorization header value
   * @returns Token string or null
   */
  static extractBearerToken(authHeader: string | undefined): string | null {
    if (!authHeader) {
      return null;
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return null;
    }

    return parts[1];
  }
}
```

---

## Models

### src/models/user.model.ts

```typescript
import { User } from '../types';
import { PasswordUtil } from '../utils/password.util';

/**
 * In-memory user database (replace with actual database in production)
 */
class UserModel {
  private users: User[] = [];

  /**
   * Create a new user
   * @param login - User login
   * @param password - Plain text password (will be hashed)
   * @returns Created user object (without password hash)
   */
  async createUser(login: string, password: string): Promise<Omit<User, 'passwordHash'>> {
    // Check if user already exists
    const existingUser = this.users.find((u) => u.login === login);
    if (existingUser) {
      throw new Error('User with this login already exists');
    }

    // Hash the password
    const passwordHash = await PasswordUtil.hashPassword(password);

    // Create new user
    const newUser: User = {
      id: this.generateId(),
      login,
      passwordHash,
      createdAt: new Date(),
    };

    this.users.push(newUser);

    // Return user without password hash
    const { passwordHash: _, ...userWithoutPassword } = newUser;
    return userWithoutPassword;
  }

  /**
   * Find user by login
   * @param login - User login
   * @returns User object or null
   */
  async findUserByLogin(login: string): Promise<User | null> {
    const user = this.users.find((u) => u.login === login);
    return user || null;
  }

  /**
   * Find user by ID
   * @param id - User ID
   * @returns User object or null
   */
  async findUserById(id: string): Promise<User | null> {
    const user = this.users.find((u) => u.id === id);
    return user || null;
  }

  /**
   * Verify user credentials
   * @param login - User login
   * @param password - Plain text password
   * @returns User object (without password) if credentials are valid, null otherwise
   */
  async verifyCredentials(
    login: string,
    password: string
  ): Promise<Omit<User, 'passwordHash'> | null> {
    const user = await this.findUserByLogin(login);
    if (!user) {
      return null;
    }

    const isPasswordValid = await PasswordUtil.comparePassword(
      password,
      user.passwordHash
    );

    if (!isPasswordValid) {
      return null;
    }

    const { passwordHash: _, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }

  /**
   * Generate unique user ID
   * @returns Unique ID string
   */
  private generateId(): string {
    return `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get all users (for debugging - remove in production)
   */
  getAllUsers(): Omit<User, 'passwordHash'>[] {
    return this.users.map(({ passwordHash, ...user }) => user);
  }
}

// Export singleton instance
export const userModel = new UserModel();
```

---

## Services

### src/services/auth.service.ts

```typescript
import { userModel } from '../models/user.model';
import { JwtUtil } from '../utils/jwt.util';
import { SignupDto, LoginDto, TokenPair, JwtPayload } from '../types';

export class AuthService {
  /**
   * Register a new user
   * @param signupDto - Signup data transfer object
   * @returns Success message
   */
  async signup(signupDto: SignupDto): Promise<{ message: string }> {
    const { login, password } = signupDto;

    try {
      await userModel.createUser(login, password);
      return { message: 'User created successfully' };
    } catch (error) {
      if (error instanceof Error && error.message.includes('already exists')) {
        throw new Error('User with this login already exists');
      }
      throw new Error('Failed to create user');
    }
  }

  /**
   * Authenticate user and generate tokens
   * @param loginDto - Login data transfer object
   * @returns Token pair
   */
  async login(loginDto: LoginDto): Promise<TokenPair> {
    const { login, password } = loginDto;

    // Verify credentials
    const user = await userModel.verifyCredentials(login, password);
    if (!user) {
      throw new Error('Invalid credentials');
    }

    // Generate tokens
    const payload: JwtPayload = {
      userId: user.id,
      login: user.login,
    };

    return JwtUtil.generateTokenPair(payload);
  }

  /**
   * Refresh access token using refresh token
   * @param refreshToken - Refresh token
   * @returns New token pair
   */
  async refresh(refreshToken: string): Promise<TokenPair> {
    try {
      // Verify refresh token
      const payload = JwtUtil.verifyRefreshToken(refreshToken);

      // Verify user still exists
      const user = await userModel.findUserById(payload.userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Generate new token pair
      const newPayload: JwtPayload = {
        userId: user.id,
        login: user.login,
      };

      return JwtUtil.generateTokenPair(newPayload);
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Token refresh failed: ${error.message}`);
      }
      throw new Error('Token refresh failed');
    }
  }
}

export const authService = new AuthService();
```

---

## Controllers

### src/controllers/auth.controller.ts

```typescript
import { Request, Response } from 'express';
import { authService } from '../services/auth.service';
import { SignupDto, LoginDto, RefreshTokenDto } from '../types';

export class AuthController {
  /**
   * Handle user signup
   * POST /auth/signup
   */
  async signup(req: Request, res: Response): Promise<void> {
    try {
      const { login, password }: SignupDto = req.body;

      // Validate input
      if (!login || !password) {
        res.status(400).json({
          message: 'Login and password are required',
        });
        return;
      }

      if (typeof login !== 'string' || typeof password !== 'string') {
        res.status(400).json({
          message: 'Login and password must be strings',
        });
        return;
      }

      // Create user
      const result = await authService.signup({ login, password });

      res.status(201).json(result);
    } catch (error) {
      if (error instanceof Error) {
        if (error.message.includes('already exists')) {
          res.status(400).json({ message: error.message });
          return;
        }
      }
      res.status(500).json({
        message: 'Internal server error during signup',
      });
    }
  }

  /**
   * Handle user login
   * POST /auth/login
   */
  async login(req: Request, res: Response): Promise<void> {
    try {
      const { login, password }: LoginDto = req.body;

      // Validate input
      if (!login || !password) {
        res.status(400).json({
          message: 'Login and password are required',
        });
        return;
      }

      if (typeof login !== 'string' || typeof password !== 'string') {
        res.status(400).json({
          message: 'Login and password must be strings',
        });
        return;
      }

      // Authenticate user
      const tokens = await authService.login({ login, password });

      res.status(200).json(tokens);
    } catch (error) {
      if (error instanceof Error && error.message === 'Invalid credentials') {
        res.status(403).json({
          message: 'Authentication failed: invalid login or password',
        });
        return;
      }
      res.status(500).json({
        message: 'Internal server error during login',
      });
    }
  }

  /**
   * Handle token refresh
   * POST /auth/refresh
   */
  async refresh(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken }: RefreshTokenDto = req.body;

      // Validate input
      if (!refreshToken) {
        res.status(401).json({
          message: 'Refresh token is required',
        });
        return;
      }

      if (typeof refreshToken !== 'string') {
        res.status(401).json({
          message: 'Refresh token must be a string',
        });
        return;
      }

      // Refresh tokens
      const tokens = await authService.refresh(refreshToken);

      res.status(200).json(tokens);
    } catch (error) {
      if (error instanceof Error) {
        if (
          error.message.includes('expired') ||
          error.message.includes('Invalid') ||
          error.message.includes('not found')
        ) {
          res.status(403).json({
            message: 'Authentication failed: invalid or expired refresh token',
          });
          return;
        }
      }
      res.status(500).json({
        message: 'Internal server error during token refresh',
      });
    }
  }
}

export const authController = new AuthController();
```

---

## Middleware

### src/middleware/auth.middleware.ts

```typescript
import { Response, NextFunction } from 'express';
import { JwtUtil } from '../utils/jwt.util';
import { AuthRequest } from '../types';

/**
 * Middleware to verify JWT access token
 * Extracts token from Authorization header and verifies it
 */
export const authMiddleware = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  try {
    // Get authorization header
    const authHeader = req.headers.authorization;

    // Extract bearer token
    const token = JwtUtil.extractBearerToken(authHeader);

    if (!token) {
      res.status(401).json({
        message: 'Authorization header missing or invalid. Expected format: Bearer <token>',
      });
      return;
    }

    // Verify token
    try {
      const payload = JwtUtil.verifyAccessToken(token);
      req.user = payload;
      next();
    } catch (error) {
      if (error instanceof Error) {
        if (error.message.includes('expired')) {
          res.status(401).json({
            message: 'Access token has expired',
          });
          return;
        }
        if (error.message.includes('Invalid')) {
          res.status(401).json({
            message: 'Invalid access token',
          });
          return;
        }
      }
      res.status(401).json({
        message: 'Token verification failed',
      });
    }
  } catch (error) {
    res.status(401).json({
      message: 'Authentication failed',
    });
  }
};
```

### src/middleware/validation.middleware.ts

```typescript
import { Request, Response, NextFunction } from 'express';

/**
 * Middleware to validate request body structure
 */
export const validateBody = (requiredFields: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const missingFields = requiredFields.filter(
      (field) => !(field in req.body)
    );

    if (missingFields.length > 0) {
      res.status(400).json({
        message: `Missing required fields: ${missingFields.join(', ')}`,
      });
      return;
    }

    next();
  };
};

/**
 * Middleware to validate string fields
 */
export const validateStringFields = (fields: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const invalidFields = fields.filter(
      (field) => typeof req.body[field] !== 'string'
    );

    if (invalidFields.length > 0) {
      res.status(400).json({
        message: `Following fields must be strings: ${invalidFields.join(', ')}`,
      });
      return;
    }

    next();
  };
};
```

---

## Routes

### src/routes/auth.routes.ts

```typescript
import { Router } from 'express';
import { authController } from '../controllers/auth.controller';

const router = Router();

/**
 * @route   POST /auth/signup
 * @desc    Register a new user
 * @access  Public
 */
router.post('/signup', (req, res) => authController.signup(req, res));

/**
 * @route   POST /auth/login
 * @desc    Authenticate user and get tokens
 * @access  Public
 */
router.post('/login', (req, res) => authController.login(req, res));

/**
 * @route   POST /auth/refresh
 * @desc    Refresh access token using refresh token
 * @access  Public
 */
router.post('/refresh', (req, res) => authController.refresh(req, res));

export default router;
```

---

## Application Entry

### src/app.ts

```typescript
import express, { Application, Request, Response, NextFunction } from 'express';
import config from './config/environment';
import authRoutes from './routes/auth.routes';
import { authMiddleware } from './middleware/auth.middleware';
import { AuthRequest } from './types';

const app: Application = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Root endpoint
app.get('/', (req: Request, res: Response) => {
  res.json({
    message: 'JWT Authentication API',
    version: '1.0.0',
    endpoints: {
      signup: 'POST /auth/signup',
      login: 'POST /auth/login',
      refresh: 'POST /auth/refresh',
      protected: 'GET /protected (example)',
      documentation: 'GET /doc (if implemented)',
    },
  });
});

// Documentation endpoint (placeholder)
app.get('/doc', (req: Request, res: Response) => {
  res.json({
    message: 'API Documentation',
    endpoints: [
      {
        method: 'POST',
        path: '/auth/signup',
        description: 'Register a new user',
        body: { login: 'string', password: 'string' },
        responses: {
          201: 'User created successfully',
          400: 'Invalid input',
        },
      },
      {
        method: 'POST',
        path: '/auth/login',
        description: 'Authenticate and receive tokens',
        body: { login: 'string', password: 'string' },
        responses: {
          200: 'Returns accessToken and refreshToken',
          400: 'Invalid input',
          403: 'Authentication failed',
        },
      },
      {
        method: 'POST',
        path: '/auth/refresh',
        description: 'Get new token pair using refresh token',
        body: { refreshToken: 'string' },
        responses: {
          200: 'Returns new accessToken and refreshToken',
          401: 'Invalid input',
          403: 'Invalid or expired refresh token',
        },
      },
    ],
  });
});

// Auth routes (public)
app.use('/auth', authRoutes);

// Example protected route
app.get('/protected', authMiddleware, (req: AuthRequest, res: Response) => {
  res.json({
    message: 'This is a protected route',
    user: req.user,
  });
});

// Apply auth middleware to all other routes (except auth, doc, and root)
app.use((req: Request, res: Response, next: NextFunction) => {
  // Skip authentication for specific routes
  const publicRoutes = ['/', '/doc', '/auth/signup', '/auth/login', '/auth/refresh'];
  
  if (publicRoutes.includes(req.path) || req.path.startsWith('/auth/')) {
    return next();
  }

  // Apply authentication
  authMiddleware(req as AuthRequest, res, next);
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    message: 'Route not found',
  });
});

// Error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({
    message: 'Internal server error',
    error: config.nodeEnv === 'development' ? err.message : undefined,
  });
});

// Start server
const PORT = config.port;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
  console.log(`📍 Environment: ${config.nodeEnv}`);
  console.log(`🔐 JWT Access Token Expiration: ${config.jwt.accessExpiration}`);
  console.log(`🔐 JWT Refresh Token Expiration: ${config.jwt.refreshExpiration}`);
  console.log(`\n📚 API Endpoints:`);
  console.log(`   POST http://localhost:${PORT}/auth/signup`);
  console.log(`   POST http://localhost:${PORT}/auth/login`);
  console.log(`   POST http://localhost:${PORT}/auth/refresh`);
  console.log(`   GET  http://localhost:${PORT}/protected (example)`);
});

export default app;
```

---

## Testing

### Test with cURL

```bash
# 1. Signup
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"login": "testuser", "password": "testpass123"}'

# Expected: 201 Created
# {"message":"User created successfully"}

# 2. Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login": "testuser", "password": "testpass123"}'

# Expected: 200 OK
# {"accessToken":"eyJhbG...","refreshToken":"eyJhbG..."}

# 3. Access Protected Route
curl -X GET http://localhost:3000/protected \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>"

# Expected: 200 OK
# {"message":"This is a protected route","user":{"userId":"...","login":"testuser"}}

# 4. Refresh Token
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "<YOUR_REFRESH_TOKEN>"}'

# Expected: 200 OK
# {"accessToken":"eyJhbG...","refreshToken":"eyJhbG..."}
```

### Test with Postman

**Collection Setup:**

1. **Signup Request**
   - Method: POST
   - URL: `http://localhost:3000/auth/signup`
   - Headers: `Content-Type: application/json`
   - Body (raw JSON):
     ```json
     {
       "login": "testuser",
       "password": "testpass123"
     }
     ```

2. **Login Request**
   - Method: POST
   - URL: `http://localhost:3000/auth/login`
   - Headers: `Content-Type: application/json`
   - Body (raw JSON):
     ```json
     {
       "login": "testuser",
       "password": "testpass123"
     }
     ```
   - Tests (to save tokens):
     ```javascript
     if (pm.response.code === 200) {
       const jsonData = pm.response.json();
       pm.environment.set("accessToken", jsonData.accessToken);
       pm.environment.set("refreshToken", jsonData.refreshToken);
     }
     ```

3. **Protected Route Request**
   - Method: GET
   - URL: `http://localhost:3000/protected`
   - Headers: `Authorization: Bearer {{accessToken}}`

4. **Refresh Token Request**
   - Method: POST
   - URL: `http://localhost:3000/auth/refresh`
   - Headers: `Content-Type: application/json`
   - Body (raw JSON):
     ```json
     {
       "refreshToken": "{{refreshToken}}"
     }
     ```

---

## Error Scenarios Testing

### 1. Invalid Signup (Missing Fields)
```bash
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"login": "testuser"}'

# Expected: 400 Bad Request
# {"message":"Login and password are required"}
```

### 2. Invalid Signup (Wrong Type)
```bash
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"login": 123, "password": "test"}'

# Expected: 400 Bad Request
# {"message":"Login and password must be strings"}
```

### 3. Invalid Login (Wrong Credentials)
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login": "testuser", "password": "wrongpass"}'

# Expected: 403 Forbidden
# {"message":"Authentication failed: invalid login or password"}
```

### 4. Access Protected Route Without Token
```bash
curl -X GET http://localhost:3000/protected

# Expected: 401 Unauthorized
# {"message":"Authorization header missing or invalid..."}
```

### 5. Access Protected Route With Invalid Token
```bash
curl -X GET http://localhost:3000/protected \
  -H "Authorization: Bearer invalid_token"

# Expected: 401 Unauthorized
# {"message":"Invalid access token"}
```

### 6. Refresh With Invalid Token
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "invalid_token"}'

# Expected: 403 Forbidden
# {"message":"Authentication failed: invalid or expired refresh token"}
```

---

## Running the Application

### Development Mode

```bash
# Install dependencies
npm install

# Create .env file with your secrets
cp .env.example .env
# Edit .env and add your secrets

# Run in development mode (with auto-reload)
npm run dev
```

### Production Build

```bash
# Build TypeScript to JavaScript
npm run build

# Run production build
npm start
```

---

## Security Best Practices

1. **Environment Variables**
   - Never commit `.env` file to version control
   - Use strong, random secrets for JWT tokens
   - Different secrets for access and refresh tokens

2. **Password Security**
   - Passwords are hashed using bcrypt with salt rounds
   - Never store plain text passwords
   - Password hash remains hashed after all operations

3. **Token Security**
   - Short expiration for access tokens (15 minutes recommended)
   - Longer expiration for refresh tokens (7 days recommended)
   - Tokens contain minimal user information

4. **Bearer Token Authentication**
   - All protected routes require proper Bearer token format
   - Tokens are verified on each request

5. **Error Handling**
   - Generic error messages to prevent information leakage
   - Detailed errors only in development mode

---

## Database Integration

The current implementation uses in-memory storage. For production, integrate with a real database:

### MongoDB Example

```typescript
// Install: npm install mongoose @types/mongoose

import mongoose, { Schema, Document } from 'mongoose';

interface IUser extends Document {
  login: string;
  passwordHash: string;
  createdAt: Date;
}

const UserSchema = new Schema<IUser>({
  login: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

export const UserModel = mongoose.model<IUser>('User', UserSchema);
```

### PostgreSQL Example

```typescript
// Install: npm install pg @types/pg

import { Pool } from 'pg';

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT || '5432'),
});

// Create users table
const createTableQuery = `
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    login VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`;
```

---

## Additional Features (Optional)

### 1. Token Blacklist for Logout

```typescript
// src/models/token-blacklist.model.ts
class TokenBlacklist {
  private blacklist: Set<string> = new Set();

  addToken(token: string): void {
    this.blacklist.add(token);
  }

  isBlacklisted(token: string): boolean {
    return this.blacklist.has(token);
  }
}

export const tokenBlacklist = new TokenBlacklist();
```

### 2. Rate Limiting

```bash
npm install express-rate-limit
```

```typescript
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per windowMs
  message: 'Too many authentication attempts, please try again later',
});

app.use('/auth/login', authLimiter);
```

### 3. Request Logging

```bash
npm install morgan @types/morgan
```

```typescript
import morgan from 'morgan';

app.use(morgan('combined'));
```

---

## Troubleshooting

### Issue: "Cannot find module" errors
**Solution:** Ensure all dependencies are installed with `npm install`

### Issue: JWT tokens not working
**Solution:** Check that JWT_ACCESS_SECRET and JWT_REFRESH_SECRET are set in `.env`

### Issue: Password comparison fails
**Solution:** Ensure bcrypt salt rounds are consistent and passwords are properly hashed

### Issue: CORS errors in browser
**Solution:** Install and configure cors middleware
```bash
npm install cors @types/cors
```
```typescript
import cors from 'cors';
app.use(cors());
```

---

## Summary

This implementation provides:

✅ Complete TypeScript setup with Node.js 20 LTS  
✅ JWT-based authentication with access and refresh tokens  
✅ Password hashing with bcrypt  
✅ Bearer token authentication scheme  
✅ Proper error handling with appropriate status codes  
✅ Environment-based configuration  
✅ Middleware for authentication  
✅ In-memory user storage (easily replaceable with database)  
✅ Complete type safety with TypeScript  
✅ RESTful API design  
✅ Production-ready structure  

All requirements from the task description are fully implemented and ready for use!
