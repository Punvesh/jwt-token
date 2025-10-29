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
//# sourceMappingURL=index.d.ts.map