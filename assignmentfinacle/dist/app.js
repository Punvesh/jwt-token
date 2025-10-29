"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const path_1 = __importDefault(require("path"));
const environment_1 = __importDefault(require("./config/environment"));
const auth_routes_1 = __importDefault(require("./routes/auth.routes"));
const auth_middleware_1 = require("./middleware/auth.middleware");
const app = (0, express_1.default)();
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: true }));
app.use(express_1.default.static(path_1.default.join(__dirname, '../public')));
app.get('/', (_req, res) => {
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
app.get('/doc', (_req, res) => {
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
app.use('/auth', auth_routes_1.default);
app.get('/protected', auth_middleware_1.authMiddleware, (req, res) => {
    res.json({
        message: 'This is a protected route',
        user: req.user,
    });
});
app.use((req, res, next) => {
    const publicRoutes = ['/', '/doc', '/auth/signup', '/auth/login', '/auth/refresh'];
    if (publicRoutes.includes(req.path) || req.path.startsWith('/auth/')) {
        return next();
    }
    (0, auth_middleware_1.authMiddleware)(req, res, next);
});
app.use((_req, res) => {
    res.status(404).json({
        message: 'Route not found',
    });
});
app.use((err, _req, res, _next) => {
    console.error('Error:', err);
    res.status(500).json({
        message: 'Internal server error',
        error: environment_1.default.nodeEnv === 'development' ? err.message : undefined,
    });
});
const PORT = environment_1.default.port;
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
    console.log(`📍 Environment: ${environment_1.default.nodeEnv}`);
    console.log(`🔐 JWT Access Token Expiration: ${environment_1.default.jwt.accessExpiration}`);
    console.log(`🔐 JWT Refresh Token Expiration: ${environment_1.default.jwt.refreshExpiration}`);
    console.log(`\n📚 API Endpoints:`);
    console.log(`   POST http://localhost:${PORT}/auth/signup`);
    console.log(`   POST http://localhost:${PORT}/auth/login`);
    console.log(`   POST http://localhost:${PORT}/auth/refresh`);
    console.log(`   GET  http://localhost:${PORT}/protected (example)`);
});
exports.default = app;
//# sourceMappingURL=app.js.map