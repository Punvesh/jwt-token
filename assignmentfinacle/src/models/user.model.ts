import { User } from '../types';
import { PasswordUtil } from '../utils/password.util';

class UserModel {
  private users: User[] = [];

  async createUser(login: string, password: string): Promise<Omit<User, 'passwordHash'>> {
    const existingUser = this.users.find((u) => u.login === login);
    if (existingUser) {
      throw new Error('User with this login already exists');
    }

    const passwordHash = await PasswordUtil.hashPassword(password);

    const newUser: User = {
      id: this.generateId(),
      login,
      passwordHash,
      createdAt: new Date(),
    };

    this.users.push(newUser);

    const { passwordHash: _, ...userWithoutPassword } = newUser;
    return userWithoutPassword;
  }

  async findUserByLogin(login: string): Promise<User | null> {
    const user = this.users.find((u) => u.login === login);
    return user || null;
  }

  async findUserById(id: string): Promise<User | null> {
    const user = this.users.find((u) => u.id === id);
    return user || null;
  }

  async verifyCredentials(
    login: string,
    password: string
  ): Promise<Omit<User, 'passwordHash'> | null> {
    const user = await this.findUserByLogin(login);
    if (!user) {
      return null;
    }

    const isPasswordValid = await PasswordUtil.comparePassword(
      password,
      user.passwordHash
    );

    if (!isPasswordValid) {
      return null;
    }

    const { passwordHash: _, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }

  private generateId(): string {
    return `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getAllUsers(): Omit<User, 'passwordHash'>[] {
    return this.users.map(({ passwordHash, ...user }) => user);
  }
}

export const userModel = new UserModel();
