import { Request, Response, NextFunction } from 'express';
export declare const validateBody: (requiredFields: string[]) => (req: Request, res: Response, next: NextFunction) => void;
export declare const validateStringFields: (fields: string[]) => (req: Request, res: Response, next: NextFunction) => void;
//# sourceMappingURL=validation.middleware.d.ts.map