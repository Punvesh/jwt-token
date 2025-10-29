import { Request, Response, NextFunction } from 'express';

export const validateBody = (requiredFields: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const missingFields = requiredFields.filter(
      (field) => !(field in req.body)
    );

    if (missingFields.length > 0) {
      res.status(400).json({
        message: `Missing required fields: ${missingFields.join(', ')}`,
      });
      return;
    }

    next();
  };
};

export const validateStringFields = (fields: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const invalidFields = fields.filter(
      (field) => typeof req.body[field] !== 'string'
    );

    if (invalidFields.length > 0) {
      res.status(400).json({
        message: `Following fields must be strings: ${invalidFields.join(', ')}`,
      });
      return;
    }

    next();
  };
};
