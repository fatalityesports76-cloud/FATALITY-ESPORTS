const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const APP_DIR = path.resolve(__dirname, "..");
const SECRETS_DIR = path.join(APP_DIR, "secrets");
const ADMIN_HASH_PATH = path.join(SECRETS_DIR, "admin-password.hash");
const ADMIN_TEMP_PASSWORD_PATH = path.join(SECRETS_DIR, "admin-temporary-password.txt");

const args = process.argv.slice(2);
const allowWeak = args.includes("--allow-weak");
const passwordArg = args.find((arg) => arg !== "--allow-weak") || "";
const password = passwordArg || process.env.ADMIN_PASSWORD || "";
if (!password || (!allowWeak && password.length < 12)) {
  console.error(
    "Uso: node scripts/set-admin-password.js \"SENHA_FORTE_COM_12+\" [--allow-weak]"
  );
  process.exit(1);
}

fs.mkdirSync(SECRETS_DIR, { recursive: true });
fs.writeFileSync(ADMIN_HASH_PATH, createPasswordHash(password) + "\n", { encoding: "utf8" });

if (fs.existsSync(ADMIN_TEMP_PASSWORD_PATH)) {
  fs.rmSync(ADMIN_TEMP_PASSWORD_PATH, { force: true });
}

console.log("Senha admin atualizada com sucesso.");
console.log(`Hash salvo em: ${ADMIN_HASH_PATH}`);

function createPasswordHash(rawPassword) {
  const N = 16384;
  const r = 8;
  const p = 1;
  const keyLength = 64;
  const salt = crypto.randomBytes(16).toString("base64url");
  const hash = crypto
    .scryptSync(rawPassword, salt, keyLength, { N, r, p, maxmem: 128 * 1024 * 1024 })
    .toString("base64url");

  return `scrypt$${N}$${r}$${p}$${salt}$${hash}`;
}
