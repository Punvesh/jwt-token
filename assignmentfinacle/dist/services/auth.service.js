"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authService = exports.AuthService = void 0;
const user_model_1 = require("../models/user.model");
const jwt_util_1 = require("../utils/jwt.util");
class AuthService {
    async signup(signupDto) {
        const { login, password } = signupDto;
        try {
            await user_model_1.userModel.createUser(login, password);
            return { message: 'User created successfully' };
        }
        catch (error) {
            if (error instanceof Error && error.message.includes('already exists')) {
                throw new Error('User with this login already exists');
            }
            throw new Error('Failed to create user');
        }
    }
    async login(loginDto) {
        const { login, password } = loginDto;
        const user = await user_model_1.userModel.verifyCredentials(login, password);
        if (!user) {
            throw new Error('Invalid credentials');
        }
        const payload = {
            userId: user.id,
            login: user.login,
        };
        return jwt_util_1.JwtUtil.generateTokenPair(payload);
    }
    async refresh(refreshToken) {
        try {
            const payload = jwt_util_1.JwtUtil.verifyRefreshToken(refreshToken);
            const user = await user_model_1.userModel.findUserById(payload.userId);
            if (!user) {
                throw new Error('User not found');
            }
            const newPayload = {
                userId: user.id,
                login: user.login,
            };
            return jwt_util_1.JwtUtil.generateTokenPair(newPayload);
        }
        catch (error) {
            if (error instanceof Error) {
                throw new Error(`Token refresh failed: ${error.message}`);
            }
            throw new Error('Token refresh failed');
        }
    }
}
exports.AuthService = AuthService;
exports.authService = new AuthService();
//# sourceMappingURL=auth.service.js.map