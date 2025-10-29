import { User } from '../types';
declare class UserModel {
    private users;
    createUser(login: string, password: string): Promise<Omit<User, 'passwordHash'>>;
    findUserByLogin(login: string): Promise<User | null>;
    findUserById(id: string): Promise<User | null>;
    verifyCredentials(login: string, password: string): Promise<Omit<User, 'passwordHash'> | null>;
    private generateId;
    getAllUsers(): Omit<User, 'passwordHash'>[];
}
export declare const userModel: UserModel;
export {};
//# sourceMappingURL=user.model.d.ts.map