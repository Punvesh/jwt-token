import { Response, NextFunction } from 'express';
import { JwtUtil } from '../utils/jwt.util';
import { AuthRequest } from '../types';

export const authMiddleware = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  try {
    const authHeader = req.headers.authorization;

    const token = JwtUtil.extractBearerToken(authHeader);

    if (!token) {
      res.status(401).json({
        message: 'Authorization header missing or invalid. Expected format: Bearer <token>',
      });
      return;
    }

    try {
      const payload = JwtUtil.verifyAccessToken(token);
      req.user = payload;
      next();
    } catch (error) {
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
  } catch (error) {
    res.status(401).json({
      message: 'Authentication failed',
    });
  }
};
