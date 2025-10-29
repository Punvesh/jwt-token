"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authController = exports.AuthController = void 0;
const auth_service_1 = require("../services/auth.service");
class AuthController {
    async signup(req, res) {
        try {
            const { login, password } = req.body;
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
            const result = await auth_service_1.authService.signup({ login, password });
            res.status(201).json(result);
        }
        catch (error) {
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
    async login(req, res) {
        try {
            const { login, password } = req.body;
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
            const tokens = await auth_service_1.authService.login({ login, password });
            res.status(200).json(tokens);
        }
        catch (error) {
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
    async refresh(req, res) {
        try {
            const { refreshToken } = req.body;
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
            const tokens = await auth_service_1.authService.refresh(refreshToken);
            res.status(200).json(tokens);
        }
        catch (error) {
            if (error instanceof Error) {
                if (error.message.includes('expired') ||
                    error.message.includes('Invalid') ||
                    error.message.includes('not found')) {
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
exports.AuthController = AuthController;
exports.authController = new AuthController();
//# sourceMappingURL=auth.controller.js.map