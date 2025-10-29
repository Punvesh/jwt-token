import { SignupDto, LoginDto, TokenPair } from '../types';
export declare class AuthService {
    signup(signupDto: SignupDto): Promise<{
        message: string;
    }>;
    login(loginDto: LoginDto): Promise<TokenPair>;
    refresh(refreshToken: string): Promise<TokenPair>;
}
export declare const authService: AuthService;
//# sourceMappingURL=auth.service.d.ts.map