"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createWalletClient = void 0;
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const auth_express_middleware_1 = require("@bsv/auth-express-middleware");
const sdk_1 = require("@bsv/sdk");
const wallet_toolbox_client_1 = require("@bsv/wallet-toolbox-client");
const signCertificate_1 = require("./signCertificate");
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const SERVER_PRIVATE_KEY = process.env.SERVER_PRIVATE_KEY;
const WALLET_STORAGE_URL = process.env.WALLET_STORAGE_URL;
const CHAIN = process.env.CHAIN;
const createWalletClient = async (keyHex, walletStorageUrl, chain) => {
    const rootKey = sdk_1.PrivateKey.fromHex(keyHex);
    const keyDeriver = new sdk_1.KeyDeriver(rootKey);
    const storage = new wallet_toolbox_client_1.WalletStorageManager(keyDeriver.identityKey);
    const services = new wallet_toolbox_client_1.Services(chain);
    const wallet = new wallet_toolbox_client_1.Wallet({
        chain,
        keyDeriver,
        storage,
        services,
    });
    const client = new wallet_toolbox_client_1.StorageClient(wallet, walletStorageUrl);
    await storage.addWalletStorageProvider(client);
    await storage.makeAvailable();
    return new sdk_1.WalletClient(wallet);
};
exports.createWalletClient = createWalletClient;
async function main() {
    // Connect to user's wallet
    const wallet = await (0, exports.createWalletClient)(SERVER_PRIVATE_KEY, WALLET_STORAGE_URL, CHAIN);
    // 2. Create the auth middleware
    //    - Set `allowUnauthenticated` to false to require mutual auth on every route
    const authMiddleware = (0, auth_express_middleware_1.createAuthMiddleware)({
        wallet,
        allowUnauthenticated: false,
        // logger: console,
        // logLevel: 'debug',
    });
    // 3. Create and configure the Express app
    const app = (0, express_1.default)();
    app.use((req, res, next) => {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Headers', '*');
        res.header('Access-Control-Allow-Methods', '*');
        res.header('Access-Control-Expose-Headers', '*');
        res.header('Access-Control-Allow-Private-Network', 'true');
        if (req.method === 'OPTIONS') {
            // Handle CORS preflight requests to allow cross-origin POST/PUT requests
            res.sendStatus(200);
        }
        else {
            next();
        }
    });
    app.use(body_parser_1.default.json());
    // 4. Apply the auth middleware globally (or to specific routes)
    app.use(authMiddleware);
    // 5. Define your routes as usual
    app.post('/signCertificate', signCertificate_1.signCertificate);
    app.listen(8080, () => {
        console.log('Server is running on port 8080');
    });
}
main();
//# sourceMappingURL=listen.js.map