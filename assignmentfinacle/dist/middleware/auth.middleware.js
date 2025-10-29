"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authMiddleware = void 0;
const jwt_util_1 = require("../utils/jwt.util");
const authMiddleware = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const token = jwt_util_1.JwtUtil.extractBearerToken(authHeader);
        if (!token) {
            res.status(401).json({
                message: 'Authorization header missing or invalid. Expected format: Bearer <token>',
            });
            return;
        }
        try {
            const payload = jwt_util_1.JwtUtil.verifyAccessToken(token);
            req.user = payload;
            next();
        }
        catch (error) {
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
    }
    catch (error) {
        res.status(401).json({
            message: 'Authentication failed',
        });
    }
};
exports.authMiddleware = authMiddleware;
//# sourceMappingURL=auth.middleware.js.map