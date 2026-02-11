const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const APP_DIR = path.resolve(__dirname, "..");
const KEYS_DIR = path.join(APP_DIR, "keys");
const SECRETS_DIR = path.join(APP_DIR, "secrets");
const DATA_DIR = path.join(APP_DIR, "data");
const LOGS_DIR = path.join(APP_DIR, "logs");

const PUBLIC_KEY_PATH = path.join(KEYS_DIR, "e2e-public.pem");
const PRIVATE_KEY_PATH = path.join(SECRETS_DIR, "e2e-private.pem");
const PRIVATE_KEY_PASS_PATH = path.join(SECRETS_DIR, "e2e-private.pass.txt");
const HMAC_SECRET_PATH = path.join(SECRETS_DIR, "app-hmac.secret");
const ADMIN_HASH_PATH = path.join(SECRETS_DIR, "admin-password.hash");
const ADMIN_TEMP_PASSWORD_PATH = path.join(SECRETS_DIR, "admin-temporary-password.txt");

ensureDir(KEYS_DIR);
ensureDir(SECRETS_DIR);
ensureDir(DATA_DIR);
ensureDir(LOGS_DIR);

const summary = [];

if (!fs.existsSync(HMAC_SECRET_PATH) || !fs.readFileSync(HMAC_SECRET_PATH, "utf8").trim()) {
  writeFile(HMAC_SECRET_PATH, randomToken(64) + "\n");
  summary.push(`Novo segredo HMAC criado: ${HMAC_SECRET_PATH}`);
} else {
  summary.push(`Segredo HMAC ja existe: ${HMAC_SECRET_PATH}`);
}

if (!fs.existsSync(PUBLIC_KEY_PATH) || !fs.existsSync(PRIVATE_KEY_PATH) || !fs.existsSync(PRIVATE_KEY_PASS_PATH)) {
  const privatePass = randomToken(32);
  const pair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: privatePass
    }
  });

  writeFile(PUBLIC_KEY_PATH, pair.publicKey);
  writeFile(PRIVATE_KEY_PATH, pair.privateKey);
  writeFile(PRIVATE_KEY_PASS_PATH, privatePass + "\n");

  summary.push(`Par de chaves E2E criado: ${PUBLIC_KEY_PATH}`);
  summary.push(`Chave privada protegida em: ${PRIVATE_KEY_PATH}`);
} else {
  summary.push(`Par de chaves E2E ja existe: ${PUBLIC_KEY_PATH}`);
}

if (!fs.existsSync(ADMIN_HASH_PATH) || !fs.readFileSync(ADMIN_HASH_PATH, "utf8").trim()) {
  const adminPassword = process.env.ADMIN_PASSWORD || randomToken(18);
  const hash = createPasswordHash(adminPassword);

  writeFile(ADMIN_HASH_PATH, hash + "\n");

  if (!process.env.ADMIN_PASSWORD) {
    writeFile(
      ADMIN_TEMP_PASSWORD_PATH,
      [
        "Senha admin temporaria:",
        adminPassword,
        "",
        "Troque com: node scripts/set-admin-password.js \"NOVA_SENHA_FORTE\""
      ].join("\n")
    );
    summary.push(`Senha admin temporaria salva em: ${ADMIN_TEMP_PASSWORD_PATH}`);
  } else {
    summary.push("Hash admin criado a partir da variavel ADMIN_PASSWORD.");
  }
} else {
  summary.push(`Hash de admin ja existe: ${ADMIN_HASH_PATH}`);
}

console.log("Setup de seguranca concluido.");
summary.forEach((line) => console.log(`- ${line}`));

function ensureDir(target) {
  fs.mkdirSync(target, { recursive: true });
}

function writeFile(filePath, content) {
  fs.writeFileSync(filePath, content, { encoding: "utf8" });
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function createPasswordHash(password) {
  const N = 16384;
  const r = 8;
  const p = 1;
  const keyLength = 64;
  const salt = crypto.randomBytes(16).toString("base64url");
  const hash = crypto
    .scryptSync(password, salt, keyLength, { N, r, p, maxmem: 128 * 1024 * 1024 })
    .toString("base64url");

  return `scrypt$${N}$${r}$${p}$${salt}$${hash}`;
}
