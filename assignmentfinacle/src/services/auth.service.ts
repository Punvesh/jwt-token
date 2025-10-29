import { userModel } from '../models/user.model';
import { JwtUtil } from '../utils/jwt.util';
import { SignupDto, LoginDto, TokenPair, JwtPayload } from '../types';

export class AuthService {
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

  async login(loginDto: LoginDto): Promise<TokenPair> {
    const { login, password } = loginDto;

    const user = await userModel.verifyCredentials(login, password);
    if (!user) {
      throw new Error('Invalid credentials');
    }

    const payload: JwtPayload = {
      userId: user.id,
      login: user.login,
    };

    return JwtUtil.generateTokenPair(payload);
  }

  async refresh(refreshToken: string): Promise<TokenPair> {
    try {
      const payload = JwtUtil.verifyRefreshToken(refreshToken);

      const user = await userModel.findUserById(payload.userId);
      if (!user) {
        throw new Error('User not found');
      }

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
