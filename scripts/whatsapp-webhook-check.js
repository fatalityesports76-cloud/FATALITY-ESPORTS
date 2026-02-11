const fs = require("fs");
const path = require("path");

const APP_DIR = path.resolve(__dirname, "..");

loadLocalEnv(path.join(APP_DIR, ".env.local"));

const WHATSAPP_PROVIDER = normalizeProvider(process.env.ORG_WHATSAPP_PROVIDER || "webhook");
const WHATSAPP_WEBHOOK_URL = String(process.env.ORG_WHATSAPP_WEBHOOK_URL || "").trim();
const META_WA_PHONE_NUMBER_ID = String(process.env.ORG_META_WA_PHONE_NUMBER_ID || "").trim();
const META_WA_ACCESS_TOKEN = String(process.env.ORG_META_WA_ACCESS_TOKEN || "").trim();
const META_WA_API_VERSION = normalizeVersion(String(process.env.ORG_META_WA_API_VERSION || "v21.0"));
const META_WA_GRAPH_BASE_URL = String(
  process.env.ORG_META_WA_GRAPH_BASE_URL || "https://graph.facebook.com"
).trim();
const args = process.argv.slice(2);
const strict = args.includes("--strict");
const sendTest = args.includes("--send-test");
const toArg = getFlagValue(args, "--to");
const messageArg = getFlagValue(args, "--message");

function getFlagValue(list, flag) {
  const direct = list.find((item) => item.startsWith(`${flag}=`));
  if (direct) {
    return direct.slice(flag.length + 1);
  }

  const index = list.indexOf(flag);
  if (index >= 0 && index < list.length - 1) {
    return list[index + 1];
  }

  return "";
}

function loadLocalEnv(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const separator = trimmed.indexOf("=");
    if (separator <= 0) {
      continue;
    }

    const key = trimmed.slice(0, separator).trim();
    let value = trimmed.slice(separator + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}

function isValidHttpUrl(value) {
  try {
    const url = new URL(String(value || ""));
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

function normalizeDigits(value) {
  return String(value || "").replace(/\D+/g, "");
}

function normalizeWhatsAppDestination(raw) {
  const value = String(raw || "").trim();
  if (!value) {
    return "";
  }

  if (value.toLowerCase().startsWith("whatsapp:")) {
    return value;
  }

  const digits = normalizeDigits(value);
  if (!digits) {
    return "";
  }

  const full = digits.length === 10 || digits.length === 11 ? `55${digits}` : digits;
  return `whatsapp:+${full}`;
}

function normalizeProvider(rawValue) {
  const value = String(rawValue || "").trim().toLowerCase();
  if (value === "meta" || value === "meta_cloud" || value === "meta-whatsapp-cloud") {
    return "meta_cloud";
  }

  return "webhook";
}

function normalizeVersion(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value) {
    return "v21.0";
  }

  return value.toLowerCase().startsWith("v") ? value : `v${value}`;
}

function hasMetaConfig() {
  if (!META_WA_PHONE_NUMBER_ID || !META_WA_ACCESS_TOKEN) {
    return false;
  }

  if (!/^v\d+\.\d+$/i.test(META_WA_API_VERSION)) {
    return false;
  }

  return isValidHttpUrl(META_WA_GRAPH_BASE_URL);
}

function normalizeMetaDestination(raw) {
  const digits = normalizeDigits(raw);
  if (!digits) {
    return "";
  }

  return digits.length === 10 || digits.length === 11 ? `55${digits}` : digits;
}

async function sendWebhookTest() {
  if (!WHATSAPP_WEBHOOK_URL) {
    throw new Error("ORG_WHATSAPP_WEBHOOK_URL nao definido.");
  }

  const destination = normalizeWhatsAppDestination(toArg);
  if (!destination) {
    throw new Error("Numero de destino invalido. Use --to=5511999999999");
  }

  const payload = {
    timestamp: new Date().toISOString(),
    channel: "whatsapp",
    destination,
    message:
      messageArg ||
      "Teste Fatality: webhook WhatsApp ativo para envio de token de recuperacao.",
    meta: {
      type: "password_reset",
      userNumber: "test_user"
    }
  };

  const response = await fetch(WHATSAPP_WEBHOOK_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": "Fatality-WhatsAppWebhookCheck/1.0"
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`Webhook falhou (${response.status}): ${text || "sem corpo"}`);
  }
}

async function sendMetaTest() {
  if (!hasMetaConfig()) {
    throw new Error(
      "Meta Cloud API nao configurada. Defina ORG_META_WA_PHONE_NUMBER_ID, ORG_META_WA_ACCESS_TOKEN e ORG_META_WA_API_VERSION."
    );
  }

  const destination = normalizeMetaDestination(toArg);
  if (!destination) {
    throw new Error("Numero de destino invalido. Use --to=5511999999999");
  }

  const endpoint = `${META_WA_GRAPH_BASE_URL.replace(/\/+$/, "")}/${META_WA_API_VERSION}/${encodeURIComponent(
    META_WA_PHONE_NUMBER_ID
  )}/messages`;

  const payload = {
    messaging_product: "whatsapp",
    recipient_type: "individual",
    to: destination,
    type: "text",
    text: {
      preview_url: false,
      body:
        messageArg ||
        "Teste Fatality: Meta WhatsApp Cloud API ativa para envio de token de recuperacao."
    }
  };

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${META_WA_ACCESS_TOKEN}`,
      "Content-Type": "application/json",
      "User-Agent": "Fatality-WhatsAppCheck/1.0"
    },
    body: JSON.stringify(payload)
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      `Meta Cloud API falhou (${response.status}): ${body?.error?.message || JSON.stringify(body)}`
    );
  }
}

async function main() {
  const urlValid = isValidHttpUrl(WHATSAPP_WEBHOOK_URL);

  console.log("WhatsApp delivery check");
  console.log(`- provider: ${WHATSAPP_PROVIDER}`);

  if (WHATSAPP_PROVIDER === "meta_cloud") {
    console.log(`- meta phone_number_id: ${META_WA_PHONE_NUMBER_ID || "(vazio)"}`);
    console.log(`- meta api_version: ${META_WA_API_VERSION}`);
    console.log(`- meta graph_base_url: ${META_WA_GRAPH_BASE_URL || "(vazio)"}`);

    if (!hasMetaConfig()) {
      console.log("- status: NAO PRONTO");
      console.log(
        "  * ORG_META_WA_PHONE_NUMBER_ID / ORG_META_WA_ACCESS_TOKEN / ORG_META_WA_API_VERSION invalidos ou ausentes."
      );
      if (strict) {
        process.exitCode = 1;
      }
      return;
    }

    console.log("- status: PRONTO");
    if (!sendTest) {
      return;
    }

    if (!toArg) {
      throw new Error("Para teste use: --send-test --to=5511999999999");
    }

    await sendMetaTest();
    console.log("- envio teste (meta_cloud): OK");
    return;
  }

  console.log(`- webhook url: ${WHATSAPP_WEBHOOK_URL || "(vazio)"}`);
  if (!urlValid) {
    console.log("- status: NAO PRONTO");
    console.log("  * ORG_WHATSAPP_WEBHOOK_URL invalido ou ausente.");
    if (strict) {
      process.exitCode = 1;
    }
    return;
  }

  console.log("- status: PRONTO");
  if (!sendTest) {
    return;
  }

  if (!toArg) {
    throw new Error("Para teste use: --send-test --to=5511999999999");
  }

  await sendWebhookTest();
  console.log("- envio teste: OK");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
