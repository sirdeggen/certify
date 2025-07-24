"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.signCertificate = signCertificate;
const sdk_1 = require("@bsv/sdk");
const wallet_toolbox_client_1 = require("@bsv/wallet-toolbox-client");
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
async function makeWallet(chain, storageURL, privateKey) {
    const keyDeriver = new sdk_1.KeyDeriver(new sdk_1.PrivateKey(privateKey, 'hex'));
    const storageManager = new wallet_toolbox_client_1.WalletStorageManager(keyDeriver.identityKey);
    const signer = new wallet_toolbox_client_1.WalletSigner(chain, keyDeriver, storageManager);
    const services = new wallet_toolbox_client_1.Services(chain);
    const wallet = new wallet_toolbox_client_1.Wallet(signer, services);
    const client = new wallet_toolbox_client_1.StorageClient(wallet, storageURL);
    await client.makeAvailable();
    await storageManager.addWalletStorageProvider(client);
    return wallet;
}
async function signCertificate(request, res) {
    try {
        const req = request;
        // Body response from Metanet desktop walletclient
        const body = req.body;
        const { clientNonce, type, fields, masterKeyring } = body;
        // Get all wallet info
        const serverWallet = await makeWallet(process.env.CHAIN, process.env.WALLET_STORAGE_URL, process.env.SERVER_PRIVATE_KEY);
        const { publicKey: certifier } = await serverWallet.getPublicKey({ identityKey: true });
        const subject = req.auth.identityKey;
        console.log({ subject });
        // Decrypt certificate fields and verify them before signing
        const decryptedFields = await sdk_1.MasterCertificate.decryptFields(serverWallet, masterKeyring, fields, subject);
        console.log({ decryptedFields }); // PRODUCTION: actually check if we believe this before attesting to it
        const serverNonce = await (0, sdk_1.createNonce)(serverWallet, subject);
        // The server computes a serial number from the client and server nonces
        const { hmac } = await serverWallet.createHmac({
            data: sdk_1.Utils.toArray(clientNonce + serverNonce, 'base64'),
            protocolID: [2, 'certificate issuance'],
            keyID: serverNonce + clientNonce,
            counterparty: subject
        });
        const serialNumber = sdk_1.Utils.toBase64(hmac);
        const hashOfSerialNumber = sdk_1.Utils.toHex(sdk_1.Hash.sha256(serialNumber));
        // Creating certificate revocation tx
        const revocation = await serverWallet.createAction({
            description: 'Certificate revocation',
            outputs: [
                {
                    outputDescription: 'Certificate revocation outpoint',
                    satoshis: 1,
                    lockingScript: sdk_1.Script.fromASM(`OP_SHA256 ${hashOfSerialNumber} OP_EQUAL`).toHex(),
                    basket: 'certificate revocation',
                    customInstructions: JSON.stringify({
                        serialNumber, // the unlockingScript is just the serialNumber
                    })
                }
            ],
            options: {
                randomizeOutputs: false // this ensures the output is always at the same position at outputIndex 0
            }
        });
        console.log("revocationTxid", revocation.txid);
        // Signing the new certificate
        const signedCertificate = new sdk_1.Certificate(type, serialNumber, subject, certifier, revocation.txid + '.0', // randomizeOutputs must be set to false
        fields);
        await signedCertificate.sign(serverWallet);
        console.log("signedCertificate", signedCertificate);
        res.json({ certificate: signedCertificate, serverNonce: serverNonce });
    }
    catch (error) {
        console.error({ error });
        res.status(500).json({ error });
    }
}
//# sourceMappingURL=signCertificate.js.map