import express, { Request, Response, NextFunction } from 'express'
import bodyParser from 'body-parser'
import { createAuthMiddleware } from '@bsv/auth-express-middleware'
import { WalletClient, PrivateKey, KeyDeriver } from '@bsv/sdk'
import { WalletStorageManager, Services, Wallet, StorageClient } from '@bsv/wallet-toolbox-client'
import { signCertificate } from './signCertificate'
import dotenv from 'dotenv'
dotenv.config()

const SERVER_PRIVATE_KEY = process.env.SERVER_PRIVATE_KEY!
const WALLET_STORAGE_URL = process.env.WALLET_STORAGE_URL!
const CHAIN = process.env.CHAIN!


export const createWalletClient = async (keyHex: string, walletStorageUrl: string, chain: 'main' | 'test'): Promise<WalletClient> => {
    const rootKey = PrivateKey.fromHex(keyHex)
    const keyDeriver = new KeyDeriver(rootKey)
    const storage = new WalletStorageManager(keyDeriver.identityKey)
    const services = new Services(chain)
    const wallet = new Wallet({
        chain,
        keyDeriver,
        storage,
        services,
    })
    const client = new StorageClient(wallet, walletStorageUrl)
    await storage.addWalletStorageProvider(client)
    await storage.makeAvailable()
    return new WalletClient(wallet)
}

async function main () {
// Connect to user's wallet
const wallet = await createWalletClient(
  SERVER_PRIVATE_KEY,
  WALLET_STORAGE_URL,
  CHAIN as 'main' | 'test'
)

// 2. Create the auth middleware
//    - Set `allowUnauthenticated` to false to require mutual auth on every route
const authMiddleware = createAuthMiddleware({
  wallet,
  allowUnauthenticated: false,
  // logger: console,
  // logLevel: 'debug',
})

// 3. Create and configure the Express app
const app = express()
app.use((req: Request, res: Response, next: NextFunction) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Allow-Headers', '*')
  res.header('Access-Control-Allow-Methods', '*')
  res.header('Access-Control-Expose-Headers', '*')
  res.header('Access-Control-Allow-Private-Network', 'true')
  if (req.method === 'OPTIONS') {
    // Handle CORS preflight requests to allow cross-origin POST/PUT requests
    res.sendStatus(200)
  } else {
    next()
  }
})
app.use(bodyParser.json())

// 4. Apply the auth middleware globally (or to specific routes)
app.use(authMiddleware)

// 5. Define your routes as usual
app.post('/signCertificate', signCertificate)

app.listen(8080, () => {
  console.log('Server is running on port 8080')
})
}

main()