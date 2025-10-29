import bcrypt from 'bcrypt';
import config from '../config/environment';

export class PasswordUtil {
  static async hashPassword(password: string): Promise<string> {
    const saltRounds = config.bcrypt.saltRounds;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
  }

  static async comparePassword(
    password: string,
    hashedPassword: string
  ): Promise<boolean> {
    return await bcrypt.compare(password, hashedPassword);
  }
}
