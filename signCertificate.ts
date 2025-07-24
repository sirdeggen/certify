import { 
    PrivateKey, 
    KeyDeriver, 
    createNonce, 
    WalletInterface, 
    Utils, 
    Certificate,
    MasterCertificate,
    Script,
    Hash
} from '@bsv/sdk'
import { Request, Response } from 'express'
import { WalletStorageManager, Services, Wallet, StorageClient, WalletSigner } from '@bsv/wallet-toolbox-client'
import dotenv from 'dotenv'
dotenv.config()

interface SignCertificateRequestBody {
    clientNonce: string;
    type: string;
    fields: any; // This could be more specific based on your certificate fields structure
    masterKeyring: any; // This could be more specific based on your keyring structure
}

interface AuthenticatedRequest extends Request {
    auth: {
        identityKey: string;
    };
    body: SignCertificateRequestBody;
}

async function makeWallet(chain: string, storageURL: string, privateKey: string): Promise<WalletInterface> {
    const keyDeriver = new KeyDeriver(new PrivateKey(privateKey, 'hex'));
    const storageManager = new WalletStorageManager(keyDeriver.identityKey);
    const signer = new WalletSigner(chain as "main" | "test", keyDeriver, storageManager);
    const services = new Services(chain as "main" | "test");
    const wallet = new Wallet(signer, services);
    const client = new StorageClient(
        wallet,
        storageURL
    );
    await client.makeAvailable();
    await storageManager.addWalletStorageProvider(client);
    return wallet;
}

export async function signCertificate(request: Request, res: Response): Promise<void> {
    try {
        const req = request as AuthenticatedRequest;
        // Body response from Metanet desktop walletclient
        const body = req.body;
        const { clientNonce, type, fields, masterKeyring } = body;
        // Get all wallet info
        const serverWallet = await makeWallet(process.env.CHAIN!, process.env.WALLET_STORAGE_URL!, process.env.SERVER_PRIVATE_KEY!);
        const { publicKey: certifier } = await serverWallet.getPublicKey({ identityKey: true });
        
        const subject = req.auth.identityKey;
        // Decrypt certificate fields and verify them before signing
        const decryptedFields = await MasterCertificate.decryptFields(
            serverWallet,
            masterKeyring,
            fields,
            subject
        );

        // PRODUCTION: actually check if we believe this before attesting to it

        const serverNonce = await createNonce(serverWallet as unknown as WalletInterface, subject);

        // The server computes a serial number from the client and server nonces
        const { hmac } = await serverWallet.createHmac({
            data: Utils.toArray(clientNonce + serverNonce, 'base64'),
            protocolID: [2, 'certificate issuance'],
            keyID: serverNonce + clientNonce,
            counterparty: subject
        });
        const serialNumber = Utils.toBase64(hmac);
        const hashOfSerialNumber = Utils.toHex(Hash.sha256(serialNumber));

        // Creating certificate revocation tx
        const revocation = await serverWallet.createAction({
            description: 'Certificate revocation',
            outputs: [
                {
                    outputDescription: 'Certificate revocation outpoint',
                    satoshis: 1,
                    lockingScript: Script.fromASM(`OP_SHA256 ${hashOfSerialNumber} OP_EQUAL`).toHex(),
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

        // Signing the new certificate
        const signedCertificate = new Certificate(
            type,
            serialNumber,
            subject,
            certifier,
            revocation.txid! + '.0', // randomizeOutputs must be set to false
            fields
        );

        await signedCertificate.sign(serverWallet);

        res.json({ certificate: signedCertificate, serverNonce: serverNonce });
    } catch (error) {
        console.error({ error });
        res.status(500).json({ error });
    }
}