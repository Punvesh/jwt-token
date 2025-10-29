interface Config {
    port: number;
    nodeEnv: string;
    jwt: {
        accessSecret: string;
        refreshSecret: string;
        accessExpiration: string;
        refreshExpiration: string;
    };
    bcrypt: {
        saltRounds: number;
    };
}
declare const config: Config;
export default config;
//# sourceMappingURL=environment.d.ts.map