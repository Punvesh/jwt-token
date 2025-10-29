import { Request, Response } from 'express';
import { authService } from '../services/auth.service';
import { SignupDto, LoginDto, RefreshTokenDto } from '../types';

export class AuthController {
  async signup(req: Request, res: Response): Promise<void> {
    try {
      const { login, password }: SignupDto = req.body;

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

  async login(req: Request, res: Response): Promise<void> {
    try {
      const { login, password }: LoginDto = req.body;

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

  async refresh(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken }: RefreshTokenDto = req.body;

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
