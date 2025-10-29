"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.userModel = void 0;
const password_util_1 = require("../utils/password.util");
class UserModel {
    constructor() {
        this.users = [];
    }
    async createUser(login, password) {
        const existingUser = this.users.find((u) => u.login === login);
        if (existingUser) {
            throw new Error('User with this login already exists');
        }
        const passwordHash = await password_util_1.PasswordUtil.hashPassword(password);
        const newUser = {
            id: this.generateId(),
            login,
            passwordHash,
            createdAt: new Date(),
        };
        this.users.push(newUser);
        const { passwordHash: _, ...userWithoutPassword } = newUser;
        return userWithoutPassword;
    }
    async findUserByLogin(login) {
        const user = this.users.find((u) => u.login === login);
        return user || null;
    }
    async findUserById(id) {
        const user = this.users.find((u) => u.id === id);
        return user || null;
    }
    async verifyCredentials(login, password) {
        const user = await this.findUserByLogin(login);
        if (!user) {
            return null;
        }
        const isPasswordValid = await password_util_1.PasswordUtil.comparePassword(password, user.passwordHash);
        if (!isPasswordValid) {
            return null;
        }
        const { passwordHash: _, ...userWithoutPassword } = user;
        return userWithoutPassword;
    }
    generateId() {
        return `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }
    getAllUsers() {
        return this.users.map(({ passwordHash, ...user }) => user);
    }
}
exports.userModel = new UserModel();
//# sourceMappingURL=user.model.js.map