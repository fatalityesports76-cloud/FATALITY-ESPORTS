const fs = require("fs");
const path = require("path");

const API_BASE = "https://api.cloudflare.com/client/v4";
const token = process.env.CLOUDFLARE_API_TOKEN || "";
const zoneId = process.env.CLOUDFLARE_ZONE_ID || "";
const domain = String(process.env.CLOUDFLARE_PRIMARY_DOMAIN || "").trim();
const dryRun = String(process.env.CLOUDFLARE_DRY_RUN || "false").toLowerCase() === "true";
const continueOnError =
  String(process.env.CLOUDFLARE_CONTINUE_ON_ERROR || "false").toLowerCase() === "true";

async function main() {
  if (!token || !zoneId || !domain) {
    console.error(
      "Defina CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID e CLOUDFLARE_PRIMARY_DOMAIN."
    );
    console.error("Use o arquivo .cloudflare.env.example como base.");
    process.exit(1);
  }

  console.log("Aplicando hardening Cloudflare...");
  console.log(`Zone: ${zoneId}`);
  console.log(`Dominio: ${domain}`);
  if (dryRun) {
    console.log("Modo dry-run habilitado (nao aplica alteracoes).");
  }

  await validateZoneAccess();

  await applyZoneSettings();
  await applyManagedWaf();
  await applyCustomFirewallRules();
  await applyRateLimitRules();

  console.log("Hardening Cloudflare finalizado.");
}

async function applyZoneSettings() {
  const settings = [
    ["always_use_https", "on"],
    ["automatic_https_rewrites", "on"],
    ["ssl", "strict"],
    ["min_tls_version", "1.2"],
    ["tls_1_3", "on"],
    ["security_level", "high"],
    ["browser_check", "on"],
    ["challenge_ttl", 1800],
    ["http3", "on"],
    ["brotli", "on"],
    ["0rtt", "off"],
    ["opportunistic_encryption", "on"],
    ["waf", "on"],
    ["bot_fight_mode", "on"]
  ];

  for (const [setting, value] of settings) {
    const endpoint = `/zones/${zoneId}/settings/${setting}`;
    if (dryRun) {
      console.log(`[dry-run] PATCH ${endpoint} => ${JSON.stringify({ value })}`);
      continue;
    }

    const result = await cfRequest("PATCH", endpoint, { value }, continueOnError);
    if (result) {
      console.log(`- setting ${setting}: ok`);
    }
  }
}

async function applyManagedWaf() {
  const endpoint = `/zones/${zoneId}/rulesets/phases/http_request_firewall_managed/entrypoint`;
  const body = {
    rules: [
      {
        action: "execute",
        expression: `http.host eq \"${domain}\"`,
        description: "Enable Cloudflare Managed Ruleset",
        action_parameters: {
          id: "efb7b8c949ac4650a09736fc376e9aee"
        },
        enabled: true
      }
    ]
  };

  if (dryRun) {
    console.log(`[dry-run] PUT ${endpoint}`);
    return;
  }

  await cfRequest("PUT", endpoint, body, continueOnError);
  console.log("- managed WAF: ok");
}

async function applyCustomFirewallRules() {
  const endpoint = `/zones/${zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint`;
  const body = {
    rules: [
      {
        action: "block",
        expression: `http.host eq \"${domain}\" and not http.request.method in {\"GET\" \"POST\" \"HEAD\" \"OPTIONS\"}`,
        description: "Block disallowed HTTP methods",
        enabled: true
      },
      {
        action: "managed_challenge",
        expression:
          `http.host eq \"${domain}\" and http.request.uri.path eq \"/api/admin/login\" and http.request.method eq \"POST\"`,
        description: "Challenge admin login attempts at edge",
        enabled: true
      },
      {
        action: "managed_challenge",
        expression:
          `http.host eq \"${domain}\" and http.request.uri.path contains \"/wp-\"`,
        description: "Challenge common bot scans",
        enabled: true
      }
    ]
  };

  if (dryRun) {
    console.log(`[dry-run] PUT ${endpoint}`);
    return;
  }

  await cfRequest("PUT", endpoint, body, continueOnError);
  console.log("- custom firewall rules: ok");
}

async function applyRateLimitRules() {
  const endpoint = `/zones/${zoneId}/rulesets/phases/http_ratelimit/entrypoint`;

  const body = {
    rules: [
      {
        action: "block",
        expression:
          `http.host eq \"${domain}\" and http.request.uri.path eq \"/api/admin/login\" and http.request.method eq \"POST\"`,
        description: "Edge rate limit for admin login",
        enabled: true,
        ratelimit: {
          characteristics: ["ip.src"],
          period: 60,
          requests_per_period: 5,
          mitigation_timeout: 3600
        }
      },
      {
        action: "managed_challenge",
        expression:
          `http.host eq \"${domain}\" and http.request.uri.path eq \"/api/security/bootstrap\" and http.request.method eq \"GET\"`,
        description: "Edge rate limit for security bootstrap",
        enabled: true,
        ratelimit: {
          characteristics: ["ip.src"],
          period: 60,
          requests_per_period: 20,
          mitigation_timeout: 900
        }
      },
      {
        action: "managed_challenge",
        expression:
          `http.host eq \"${domain}\" and http.request.uri.path eq \"/api/recruitment\" and http.request.method eq \"POST\"`,
        description: "Edge rate limit for recruitment API",
        enabled: true,
        ratelimit: {
          characteristics: ["ip.src"],
          period: 60,
          requests_per_period: 8,
          mitigation_timeout: 1800
        }
      }
    ]
  };

  if (dryRun) {
    console.log(`[dry-run] PUT ${endpoint}`);
    return;
  }

  await cfRequest("PUT", endpoint, body, continueOnError);
  console.log("- edge rate limit rules: ok");
}

async function validateZoneAccess() {
  const endpoint = `/zones/${zoneId}`;
  if (dryRun) {
    console.log(`[dry-run] GET ${endpoint}`);
    return;
  }

  const payload = await cfRequest("GET", endpoint, null, false);
  if (!payload?.result?.id) {
    throw new Error("Nao foi possivel validar acesso a zona Cloudflare.");
  }

  console.log("- credenciais Cloudflare validadas");
}

async function cfRequest(method, endpoint, body, continueOnError = false) {
  const url = `${API_BASE}${endpoint}`;
  const headers = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json"
  };

  const response = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  if (!response.ok || payload?.success === false) {
    const firstError = payload?.errors?.[0]?.message || `${response.status} ${response.statusText}`;
    const detail = payload?.errors ? JSON.stringify(payload.errors) : "";
    const message = `Cloudflare API error: ${endpoint} -> ${firstError} ${detail}`;

    if (continueOnError) {
      console.warn(message);
      return null;
    }

    throw new Error(message);
  }

  return payload;
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
