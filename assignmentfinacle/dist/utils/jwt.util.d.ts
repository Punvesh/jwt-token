import { JwtPayload, TokenPair } from '../types';
export declare class JwtUtil {
    static generateAccessToken(payload: JwtPayload): string;
    static generateRefreshToken(payload: JwtPayload): string;
    static generateTokenPair(payload: JwtPayload): TokenPair;
    static verifyAccessToken(token: string): JwtPayload;
    static verifyRefreshToken(token: string): JwtPayload;
    static extractBearerToken(authHeader: string | undefined): string | null;
}
//# sourceMappingURL=jwt.util.d.ts.map