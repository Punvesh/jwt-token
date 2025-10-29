"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateStringFields = exports.validateBody = void 0;
const validateBody = (requiredFields) => {
    return (req, res, next) => {
        const missingFields = requiredFields.filter((field) => !(field in req.body));
        if (missingFields.length > 0) {
            res.status(400).json({
                message: `Missing required fields: ${missingFields.join(', ')}`,
            });
            return;
        }
        next();
    };
};
exports.validateBody = validateBody;
const validateStringFields = (fields) => {
    return (req, res, next) => {
        const invalidFields = fields.filter((field) => typeof req.body[field] !== 'string');
        if (invalidFields.length > 0) {
            res.status(400).json({
                message: `Following fields must be strings: ${invalidFields.join(', ')}`,
            });
            return;
        }
        next();
    };
};
exports.validateStringFields = validateStringFields;
//# sourceMappingURL=validation.middleware.js.map