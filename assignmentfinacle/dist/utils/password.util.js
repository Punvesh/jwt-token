"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PasswordUtil = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const environment_1 = __importDefault(require("../config/environment"));
class PasswordUtil {
    static async hashPassword(password) {
        const saltRounds = environment_1.default.bcrypt.saltRounds;
        const hashedPassword = await bcrypt_1.default.hash(password, saltRounds);
        return hashedPassword;
    }
    static async comparePassword(password, hashedPassword) {
        return await bcrypt_1.default.compare(password, hashedPassword);
    }
}
exports.PasswordUtil = PasswordUtil;
//# sourceMappingURL=password.util.js.map