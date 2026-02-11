const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const APP_DIR = path.resolve(__dirname, "..");
const DEFAULT_INPUT = path.join(APP_DIR, "data", "submissions.jsonl");
const DEFAULT_OUTPUT = path.join(APP_DIR, "data", "submissions.decrypted.json");
const DEFAULT_PRIVATE_KEY = path.join(APP_DIR, "secrets", "e2e-private.pem");
const DEFAULT_PRIVATE_PASS = path.join(APP_DIR, "secrets", "e2e-private.pass.txt");

const options = parseArgs(process.argv.slice(2));

const inputPath = options.input || DEFAULT_INPUT;
const outputPath = options.output || DEFAULT_OUTPUT;
const privateKeyPath = options.privateKey || DEFAULT_PRIVATE_KEY;
const passphrasePath = options.passphraseFile || DEFAULT_PRIVATE_PASS;

if (!fs.existsSync(inputPath)) {
  console.error(`Arquivo de inscricoes nao encontrado: ${inputPath}`);
  process.exit(1);
}

if (!fs.existsSync(privateKeyPath)) {
  console.error(`Chave privada nao encontrada: ${privateKeyPath}`);
  process.exit(1);
}

const passphrase = options.passphrase || readIfExists(passphrasePath).trim();
if (!passphrase) {
  console.error("Passphrase da chave privada nao encontrada.");
  process.exit(1);
}

const privateKeyPem = fs.readFileSync(privateKeyPath, "utf8");
const lines = fs
  .readFileSync(inputPath, "utf8")
  .split(/\r?\n/)
  .filter((line) => line.trim().length > 0);

const decryptedItems = [];
const failures = [];

for (const line of lines) {
  let record;
  try {
    record = JSON.parse(line);
  } catch {
    failures.push({ reason: "json_parse" });
    continue;
  }

  try {
    const envelope = record?.encryption?.envelope;
    const wrappedKey = Buffer.from(String(envelope.wrappedKey || ""), "base64");
    const iv = Buffer.from(String(envelope.iv || ""), "base64");
    const combinedCiphertext = Buffer.from(String(envelope.ciphertext || ""), "base64");

    if (iv.length !== 12 || combinedCiphertext.length < 17 || wrappedKey.length < 32) {
      throw new Error("invalid_envelope");
    }

    const aesKey = crypto.privateDecrypt(
      {
        key: privateKeyPem,
        passphrase,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      wrappedKey
    );

    const authTag = combinedCiphertext.subarray(combinedCiphertext.length - 16);
    const ciphertext = combinedCiphertext.subarray(0, combinedCiphertext.length - 16);

    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
    decipher.setAuthTag(authTag);

    const plaintextBuffer = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const plaintext = plaintextBuffer.toString("utf8");

    decryptedItems.push({
      id: record.id,
      receivedAt: record.receivedAt,
      ipHash: record.ipHash,
      userAgentHash: record.userAgentHash,
      payload: JSON.parse(plaintext)
    });
  } catch (error) {
    failures.push({ id: record?.id || null, reason: String(error.message || "decrypt_failed") });
  }
}

const output = {
  generatedAt: new Date().toISOString(),
  total: lines.length,
  decrypted: decryptedItems.length,
  failed: failures.length,
  failures,
  items: decryptedItems
};

fs.writeFileSync(outputPath, JSON.stringify(output, null, 2), { encoding: "utf8" });

console.log("Descriptografia concluida.");
console.log(`Entrada: ${inputPath}`);
console.log(`Saida: ${outputPath}`);
console.log(`Registros descriptografados: ${decryptedItems.length}/${lines.length}`);

function parseArgs(argv) {
  const parsed = {};

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    const next = argv[index + 1];

    if (token === "--input" && next) {
      parsed.input = path.resolve(next);
      index += 1;
      continue;
    }

    if (token === "--output" && next) {
      parsed.output = path.resolve(next);
      index += 1;
      continue;
    }

    if (token === "--private-key" && next) {
      parsed.privateKey = path.resolve(next);
      index += 1;
      continue;
    }

    if (token === "--passphrase" && next) {
      parsed.passphrase = next;
      index += 1;
      continue;
    }

    if (token === "--passphrase-file" && next) {
      parsed.passphraseFile = path.resolve(next);
      index += 1;
    }
  }

  return parsed;
}

function readIfExists(filePath) {
  if (!fs.existsSync(filePath)) {
    return "";
  }

  return fs.readFileSync(filePath, "utf8");
}
