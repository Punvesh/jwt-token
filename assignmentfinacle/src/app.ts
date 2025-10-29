import express, { Application, Request, Response, NextFunction } from 'express';
import path from 'path';
import config from './config/environment';
import authRoutes from './routes/auth.routes';
import { authMiddleware } from './middleware/auth.middleware';
import { AuthRequest } from './types';

const app: Application = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

app.get('/', (_req: Request, res: Response) => {
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

app.get('/doc', (_req: Request, res: Response) => {
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

app.use('/auth', authRoutes);

app.get('/protected', authMiddleware, (req: AuthRequest, res: Response) => {
  res.json({
    message: 'This is a protected route',
    user: req.user,
  });
});

app.use((req: Request, res: Response, next: NextFunction) => {
  const publicRoutes = ['/', '/doc', '/auth/signup', '/auth/login', '/auth/refresh'];
  
  if (publicRoutes.includes(req.path) || req.path.startsWith('/auth/')) {
    return next();
  }

  authMiddleware(req as AuthRequest, res, next);
});

app.use((_req: Request, res: Response) => {
  res.status(404).json({
    message: 'Route not found',
  });
});

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({
    message: 'Internal server error',
    error: config.nodeEnv === 'development' ? err.message : undefined,
  });
});

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
