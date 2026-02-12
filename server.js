const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const net = require("net");
const path = require("path");

const express = require("express");
const cookieParser = require("cookie-parser");
const compression = require("compression");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { z } = require("zod");

const APP_DIR = __dirname;
const CERT_DIR = path.join(APP_DIR, "certs");
const CONFIG_DIR = path.join(APP_DIR, "config");
const KEYS_DIR = path.join(APP_DIR, "keys");
const DATA_DIR = path.join(APP_DIR, "data");
const LOGS_DIR = path.join(APP_DIR, "logs");
const SCRIPTS_DIR = path.join(APP_DIR, "scripts");
const SECRETS_DIR = path.join(APP_DIR, "secrets");

const SUBMISSIONS_PATH = path.join(DATA_DIR, "submissions.jsonl");
const AUDIT_PATH = path.join(LOGS_DIR, "security-audit.jsonl");
const ORG_AUTH_STORE_PATH = path.join(DATA_DIR, "org-auth-store.json");
const ORG_DELIVERY_LOG_PATH = path.join(LOGS_DIR, "org-delivery-log.jsonl");
const APP_HMAC_SECRET_PATH = path.join(SECRETS_DIR, "app-hmac.secret");
const ADMIN_HASH_PATH = path.join(SECRETS_DIR, "admin-password.hash");
const ADMIN_TEMP_PASSWORD_PATH = path.join(SECRETS_DIR, "admin-temporary-password.txt");
const ORG_OWNER_BOOTSTRAP_PATH = path.join(SECRETS_DIR, "org-owner-bootstrap.txt");
const E2E_PUBLIC_KEY_PATH = path.join(KEYS_DIR, "e2e-public.pem");
const E2E_PRIVATE_KEY_PATH = path.join(SECRETS_DIR, "e2e-private.pem");
const E2E_PRIVATE_PASS_PATH = path.join(SECRETS_DIR, "e2e-private.pass.txt");
const CLOUDFLARE_IPS_PATH = path.join(CONFIG_DIR, "cloudflare-ips.txt");

const CSRF_COOKIE = "__Host-fatality_csrf";
const CSRF_SIG_COOKIE = "__Host-fatality_csrf_sig";
const SESSION_COOKIE = "__Host-fatality_session";
const ORG_SESSION_COOKIE = "__Host-fatality_org_session";

ensureDir(CERT_DIR);
ensureDir(CONFIG_DIR);
ensureDir(KEYS_DIR);
ensureDir(DATA_DIR);
ensureDir(LOGS_DIR);
ensureDir(SCRIPTS_DIR);
ensureDir(SECRETS_DIR);
loadLocalEnv(path.join(APP_DIR, ".env.local"));

const HOST = process.env.HOST || "127.0.0.1";
const HTTP_PORTS = parsePortList(process.env.PORTS_HTTP || process.env.PORT, [80, 8080]);
const HTTPS_PORTS = parsePortList(process.env.PORTS_HTTPS || process.env.HTTPS_PORT, [443, 8443]);
const PUBLIC_PRIMARY_DOMAIN = String(
  process.env.PUBLIC_PRIMARY_DOMAIN || "fatality-e-sports-official.com.br"
)
  .trim()
  .toLowerCase();
const LOCAL_FALLBACK_DOMAINS = parseDomainList(
  process.env.LOCAL_FALLBACK_DOMAINS || "fatality.local,fatality.lvh.me"
);
const trustProxyValue = parseTrustProxy(process.env.TRUST_PROXY || "0");
const useCloudflareConnectingIp =
  String(process.env.USE_CLOUDFLARE_CONNECTING_IP || "false").toLowerCase() === "true";
const cloudflareProxyChecker = buildCloudflareProxyChecker(CLOUDFLARE_IPS_PATH);

const HTTPS_PFX_PATH = process.env.HTTPS_PFX_PATH || path.join(CERT_DIR, "fatality-local.pfx");
const HTTPS_PFX_PASSWORD_FILE =
  process.env.HTTPS_PFX_PASSWORD_FILE || path.join(CERT_DIR, "fatality-local.pass.txt");
const USE_PLATFORM_TLS =
  String(process.env.USE_PLATFORM_TLS || "false").toLowerCase() === "true";

const APP_HMAC_SECRET = getOrCreateSecret(APP_HMAC_SECRET_PATH, 48);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD_HASH = ensureAdminPasswordHash();
const DUMMY_PASSWORD_HASH = createPasswordHash("fatality-dummy-password");
const ADMIN_SURFACE_ENABLED =
  String(process.env.ENABLE_ADMIN_SURFACE || "false").toLowerCase() === "true";

const ORG_ROLE_VALUES = [
  "player",
  "vice_lider",
  "staff",
  "adm",
  "lider",
  "dono"
];
const ORG_IDENTIFICATION_VALUES = [
  "Homem cisgenero",
  "Mulher cisgenero",
  "Homem trans",
  "Mulher trans",
  "Transexual",
  "Travesti",
  "Nao binario",
  "Genero fluido",
  "Agenero",
  "Intersexo",
  "Outro",
  "Prefiro nao informar"
];
const ORG_ROLE_SET = new Set(ORG_ROLE_VALUES);
const ORG_PLAYER_ROLE = "player";
const ORG_STAFF_ROLE = "staff";
const ORG_OWNER_ROLE = "dono";
const ORG_LEADER_ROLE = "lider";
const ORG_VICE_LEADER_ROLE = "vice_lider";
const ORG_ADMIN_ROLE = "adm";
const ORG_APPROVAL_ROLES = [ORG_OWNER_ROLE, ORG_LEADER_ROLE, ORG_VICE_LEADER_ROLE, ORG_ADMIN_ROLE];
const ORG_FULL_MANAGEMENT_ROLES = [ORG_OWNER_ROLE, ORG_LEADER_ROLE];
const ORG_PERFORMANCE_EDITOR_ROLES = [
  ORG_OWNER_ROLE,
  ORG_LEADER_ROLE,
  ORG_VICE_LEADER_ROLE,
  ORG_ADMIN_ROLE,
  ORG_STAFF_ROLE
];
const ORG_PERFORMANCE_CATEGORIES = [
  { key: "disciplina", label: "Disciplina" },
  { key: "comunicacao", label: "Comunicação" },
  { key: "macro", label: "Macro" },
  { key: "micro", label: "Micro" },
  { key: "mentalidade", label: "Mentalidade" },
  { key: "disponibilidade", label: "Disponibilidade" }
];
const ORG_PERFORMANCE_CATEGORY_KEYS = ORG_PERFORMANCE_CATEGORIES.map((item) => item.key);
const OWNER_FIXED_NUMBERS = parseFixedUserNumbers(process.env.ORG_OWNER_FIXED_NUMBERS || "900001");
const ORG_SHOW_DELIVERY_DEBUG =
  String(process.env.ORG_SHOW_DELIVERY_DEBUG || "true").toLowerCase() === "true";
const enforceOrgSessionBinding =
  String(process.env.ORG_ENFORCE_SESSION_BINDING || "false").toLowerCase() === "true";
const ORG_EMAIL_PROVIDER = String(process.env.ORG_EMAIL_PROVIDER || "webhook").toLowerCase().trim();
const ORG_WHATSAPP_PROVIDER = normalizeOrgWhatsAppProvider(
  process.env.ORG_WHATSAPP_PROVIDER || "webhook"
);
const ORG_WHATSAPP_WEBHOOK_URL = String(process.env.ORG_WHATSAPP_WEBHOOK_URL || "").trim();
const ORG_META_WA_PHONE_NUMBER_ID = String(
  process.env.ORG_META_WA_PHONE_NUMBER_ID || process.env.ORG_META_WHATSAPP_PHONE_NUMBER_ID || ""
).trim();
const ORG_META_WA_ACCESS_TOKEN = String(
  process.env.ORG_META_WA_ACCESS_TOKEN ||
    process.env.ORG_META_WHATSAPP_ACCESS_TOKEN ||
    process.env.ORG_META_WHATSAPP_TOKEN ||
    process.env.ORG_META_WHATSAPP_API_TOKEN ||
    ""
).trim();
const ORG_META_WA_API_VERSION = String(
  process.env.ORG_META_WA_API_VERSION || process.env.ORG_META_WHATSAPP_API_VERSION || "v21.0"
).trim();
const ORG_META_WA_GRAPH_BASE_URL = String(
  process.env.ORG_META_WA_GRAPH_BASE_URL ||
    process.env.ORG_META_WHATSAPP_GRAPH_BASE_URL ||
    "https://graph.facebook.com"
).trim();
const ORG_EMAIL_WEBHOOK_URL = String(process.env.ORG_EMAIL_WEBHOOK_URL || "").trim();
const ORG_EMAIL_FROM = String(
  process.env.ORG_EMAIL_FROM || "Fatality <no-reply@fatality-e-sports-official.com.br>"
).trim();
const ORG_EMAIL_SUBJECT_PREFIX = String(process.env.ORG_EMAIL_SUBJECT_PREFIX || "[Fatality Org]").trim();
const ORG_RESEND_API_KEY = String(process.env.ORG_RESEND_API_KEY || "").trim();

ensureE2EKeypair();
initializeOrgStore();
logOrgDeliveryConfigStatus();

const publicKeyPem = fs.readFileSync(E2E_PUBLIC_KEY_PATH, "utf8");
const publicKeyObject = crypto.createPublicKey(publicKeyPem);
const publicKeySpkiDer = publicKeyObject.export({ type: "spki", format: "der" });
const PUBLIC_KEY_SPKI_BASE64 = Buffer.from(publicKeySpkiDer).toString("base64");
const PUBLIC_KEY_ID = createSha256Hex(publicKeySpkiDer).slice(0, 16);
const E2E_PRIVATE_KEY_PEM = fs.readFileSync(E2E_PRIVATE_KEY_PATH, "utf8");
const E2E_PRIVATE_KEY_PASSPHRASE = fs.readFileSync(E2E_PRIVATE_PASS_PATH, "utf8").trim();

const sessions = new Map();
const orgSessions = new Map();
const performanceEventClients = new Set();
const sessionTtlMs = 8 * 60 * 60 * 1000;
const orgSessionTtlMs = 12 * 60 * 60 * 1000;
const csrfTtlMs = 2 * 60 * 60 * 1000;
const ipRisk = new Map();
const ipConnectionCount = new Map();

const riskDecayMs = Number.parseInt(process.env.RISK_DECAY_MS || String(10 * 60 * 1000), 10);
const riskBlockMs = Number.parseInt(process.env.RISK_BLOCK_MS || String(90 * 60 * 1000), 10);
const maxRiskBeforeBlock = Number.parseInt(process.env.MAX_RISK_BEFORE_BLOCK || "12", 10);
const maxConnectionsPerIp = Number.parseInt(process.env.MAX_CONNECTIONS_PER_IP || "80", 10);
const enableIpRiskBlock =
  String(process.env.ENABLE_IP_RISK_BLOCK || "false").toLowerCase() === "true";
const riskBlockOnlyApi =
  String(process.env.RISK_BLOCK_ONLY_API || "true").toLowerCase() === "true";
const maxRequestUrlLength = 2048;
const allowedMethods = new Set(["GET", "POST", "HEAD", "OPTIONS"]);

setInterval(cleanExpiredSessions, 5 * 60 * 1000).unref();
setInterval(cleanExpiredOrgSessions, 5 * 60 * 1000).unref();
setInterval(cleanExpiredRiskStates, 5 * 60 * 1000).unref();

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", trustProxyValue);

app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader("X-Request-Id", req.requestId);
  next();
});

app.use((req, res, next) => {
  if (!useCloudflareConnectingIp) {
    next();
    return;
  }

  const headerIp = normalizeIp(req.get("cf-connecting-ip") || "");
  if (!headerIp || headerIp === "unknown") {
    next();
    return;
  }

  const remoteIp = normalizeIp(req.socket?.remoteAddress || "");
  if (isLocalIp(remoteIp) || cloudflareProxyChecker(remoteIp)) {
    next();
    return;
  }

  audit("security.cf_header_spoof_blocked", req, {
    remoteIpHash: createSha256Hex(`${APP_HMAC_SECRET}|remote|${remoteIp}`)
  });
  apiError(res, 403, "Cabecalho de proxy invalido.");
});

app.use((req, res, next) => {
  if (!enableIpRiskBlock) {
    next();
    return;
  }

  const risk = getRiskState(req);
  if (!risk || !risk.blockedUntil) {
    next();
    return;
  }

  const now = Date.now();
  if (risk.blockedUntil <= now) {
    clearRisk(req);
    next();
    return;
  }

  if (riskBlockOnlyApi && !req.path.startsWith("/api/")) {
    next();
    return;
  }

  const retryAfterSeconds = Math.ceil((risk.blockedUntil - now) / 1000);
  res.setHeader("Retry-After", String(retryAfterSeconds));
  apiError(res, 429, "IP temporariamente bloqueado por atividade suspeita.");
});

app.use((req, res, next) => {
  if (!allowedMethods.has(req.method)) {
    addRisk(req, 8, "invalid_method");
    apiError(res, 405, "Metodo nao permitido.");
    return;
  }

  if ((req.originalUrl || req.url || "").length > maxRequestUrlLength) {
    addRisk(req, 6, "url_too_long");
    apiError(res, 414, "URL muito longa.");
    return;
  }

  if (req.path.startsWith("/api/") && req.method === "POST") {
    const contentType = String(req.get("content-type") || "").toLowerCase();
    if (!contentType.startsWith("application/json")) {
      addRisk(req, 4, "invalid_content_type");
      apiError(res, 415, "Use Content-Type application/json.");
      return;
    }
  }

  next();
});

app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        imgSrc: ["'self'", "data:"],
        fontSrc: ["'self'", "data:", "https://fonts.gstatic.com"],
        connectSrc: ["'self'"],
        upgradeInsecureRequests: []
      }
    },
    referrerPolicy: { policy: "no-referrer" }
  })
);

app.use((req, res, next) => {
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

app.use(cookieParser());
app.use(express.json({ limit: "24kb", strict: true, type: "application/json" }));
app.use(
  compression({
    threshold: 1024,
    filter: (req, res) => {
      if (req.path === "/api/org/performance/events") {
        return false;
      }
      return compression.filter(req, res);
    }
  })
);

const apiLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 600,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRequestIp(req),
  handler: (req, res) => {
    addRisk(req, 3, "api_rate_limited");
    apiError(res, 429, "Muitas requisicoes. Aguarde alguns minutos.");
  }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRequestIp(req),
  skipSuccessfulRequests: true,
  handler: (req, res) => {
    addRisk(req, 6, "login_rate_limited");
    apiError(res, 429, "Muitas tentativas de login. Aguarde e tente novamente.");
  }
});

const recruitmentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRequestIp(req),
  handler: (req, res) => {
    addRisk(req, 5, "recruitment_rate_limited");
    apiError(res, 429, "Muitas inscricoes deste endereco. Aguarde e tente depois.");
  }
});

const bootstrapLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRequestIp(req),
  handler: (req, res) => {
    addRisk(req, 2, "bootstrap_rate_limited");
    apiError(res, 429, "Muitas requisicoes de bootstrap. Aguarde.");
  }
});

const healthLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRequestIp(req),
  handler: (_req, res) => {
    apiError(res, 429, "Healthcheck limitado temporariamente.");
  }
});

const orgLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRequestIp(req),
  skipSuccessfulRequests: true,
  handler: (req, res) => {
    addRisk(req, 5, "org_login_rate_limited");
    apiError(res, 429, "Muitas tentativas de login da organizacao.");
  }
});

const orgWriteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRequestIp(req),
  handler: (req, res) => {
    addRisk(req, 3, "org_write_rate_limited");
    apiError(res, 429, "Muitas operacoes em pouco tempo. Aguarde.");
  }
});

app.use("/api", (req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});
app.use("/api", apiLimiter);

const loginSchema = z.object({
  username: z.string().trim().min(1).max(64),
  password: z.string().min(8).max(160)
});

const recruitmentSchema = z.object({
  honeypot: z.string().max(120).optional().default(""),
  envelope: z.object({
    version: z.literal(1),
    wrappedKey: z.string().min(300).max(16000),
    iv: z.string().min(16).max(64),
    ciphertext: z.string().min(32).max(40000)
  }),
  client: z
    .object({
      keyId: z.string().trim().max(120).optional(),
      appVersion: z.string().trim().max(40).optional()
    })
    .optional()
    .default({})
});

const orgLoginSchema = z.object({
  userNumber: z
    .string()
    .trim()
    .regex(/^[0-9]{4,12}$/),
  password: z.string().min(8).max(160)
});

const orgRegistrationRequestSchema = z.object({
  fullName: z.string().trim().min(5).max(120),
  inGameName: z.string().trim().min(2).max(40),
  gameId: z
    .string()
    .trim()
    .regex(/^[0-9]{4,20}$/),
  serverId: z
    .string()
    .trim()
    .regex(/^[0-9]{3,20}$/),
  email: z.string().trim().toLowerCase().email().max(120),
  desiredRole: z.enum(ORG_ROLE_VALUES),
  identificacaoGenero: z.enum(ORG_IDENTIFICATION_VALUES).optional().default("Prefiro nao informar"),
  note: z.string().trim().max(240).optional().default("")
});

const recruitmentPayloadSchema = z.object({
  jogo: z.string().trim().min(2).max(40),
  nomeCompleto: z.string().trim().min(5).max(120),
  nickInGame: z.string().trim().min(2).max(40),
  eloMaximo: z.string().trim().min(2).max(60),
  wrRanked: z.number().min(0).max(100),
  maximoEstrelas: z.number().int().min(0).max(9999999),
  rotaPrincipal: z.string().trim().min(2).max(40),
  horarioDisponivel: z.string().trim().min(3).max(80),
  identificacaoGenero: z.enum(ORG_IDENTIFICATION_VALUES),
  discord: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9._]{2,32}#[0-9]{4}$/),
  idJogo: z
    .string()
    .trim()
    .regex(/^[0-9]{4,20}$/),
  serverJogo: z
    .string()
    .trim()
    .regex(/^[0-9]{3,20}$/),
  whatsapp: z
    .string()
    .trim()
    .regex(/^[0-9]{10,20}$/),
  enviadoEm: z.string().trim().datetime().optional().default(() => new Date().toISOString())
});

const orgRegisterEmailConfirmSchema = z.object({
  verificationId: z
    .string()
    .trim()
    .min(20)
    .max(80),
  code: z
    .string()
    .trim()
    .regex(/^[0-9]{6}$/)
});

const orgEmailChangeRequestSchema = z.object({
  currentPassword: z.string().min(8).max(160),
  newEmail: z.string().trim().toLowerCase().email().max(120),
  newEmailConfirm: z.string().trim().toLowerCase().email().max(120)
});

const orgResetRequestSchema = z.object({
  userNumber: z
    .string()
    .trim()
    .regex(/^[0-9]{4,12}$/),
  email: z.string().trim().toLowerCase().email().max(120),
  emailConfirm: z.string().trim().toLowerCase().email().max(120),
  newPassword: z.string().min(8).max(160)
});

const orgChangePasswordSchema = z.object({
  currentPassword: z.string().min(8).max(160),
  newPassword: z.string().min(8).max(160)
});

const orgApproveSchema = z.object({
  finalRole: z.enum(ORG_ROLE_VALUES).optional()
});

const orgRejectSchema = z.object({
  reason: z.string().trim().max(180).optional().default("")
});

const orgForceResetSchema = z.object({
  newPassword: z.string().min(8).max(160).optional()
});

const orgUpdateRoleSchema = z.object({
  role: z.enum(ORG_ROLE_VALUES)
});

const orgRemoveUserSchema = z.object({
  reason: z.string().trim().max(180).optional().default("")
});

const orgChangeCredentialSchema = z.object({
  newCredentialNumber: z
    .string()
    .trim()
    .regex(/^[0-9]{4,12}$/)
});

const orgDirectCreateUserSchema = z.object({
  fullName: z.string().trim().min(5).max(120),
  inGameName: z.string().trim().min(2).max(40),
  gameId: z
    .string()
    .trim()
    .regex(/^[0-9]{4,20}$/),
  serverId: z
    .string()
    .trim()
    .regex(/^[0-9]{3,20}$/),
  email: z.string().trim().toLowerCase().email().max(120),
  whatsapp: z
    .string()
    .trim()
    .regex(/^[0-9]{10,20}$/)
    .optional()
    .default(""),
  role: z.enum(ORG_ROLE_VALUES),
  identificacaoGenero: z.enum(ORG_IDENTIFICATION_VALUES).optional().default("Prefiro nao informar"),
  note: z.string().trim().max(240).optional().default("")
});

const orgUpdateUserProfileSchema = z.object({
  fullName: z.string().trim().min(5).max(120),
  inGameName: z.string().trim().min(2).max(40),
  gameId: z
    .string()
    .trim()
    .regex(/^[0-9]{4,20}$/),
  serverId: z
    .string()
    .trim()
    .regex(/^[0-9]{3,20}$/),
  email: z.string().trim().toLowerCase().email().max(120),
  whatsapp: z
    .string()
    .trim()
    .regex(/^[0-9]{10,20}$/)
    .optional()
    .default(""),
  identificacaoGenero: z.enum(ORG_IDENTIFICATION_VALUES).optional().default("Prefiro nao informar"),
  note: z.string().trim().max(240).optional().default("")
});

const orgPerformanceScoresSchema = z.object({
  disciplina: z.number().min(0).max(10),
  comunicacao: z.number().min(0).max(10),
  macro: z.number().min(0).max(10),
  micro: z.number().min(0).max(10),
  mentalidade: z.number().min(0).max(10),
  disponibilidade: z.number().min(0).max(10)
});

const orgPerformanceUpdateSchema = z.object({
  playerUserNumber: z
    .string()
    .trim()
    .regex(/^[0-9]{4,12}$/),
  week: z
    .string()
    .trim()
    .regex(/^[0-9]{4}-W[0-9]{2}$/)
    .optional(),
  scores: orgPerformanceScoresSchema,
  strengths: z.array(z.string().trim().min(2).max(120)).max(12).optional().default([]),
  improvements: z.array(z.string().trim().min(2).max(120)).max(12).optional().default([]),
  note: z.string().trim().max(600).optional().default("")
});

app.get("/api/healthz", healthLimiter, (_req, res) => {
  res.json({ ok: true, service: "fatality-security-backend", timestamp: new Date().toISOString() });
});

app.get("/api/security/bootstrap", bootstrapLimiter, (req, res) => {
  const csrfToken = issueCsrfToken(res);

  res.json({
    ok: true,
    csrfToken,
    crypto: {
      algorithm: "RSA-OAEP-256/AES-GCM-256",
      keyId: PUBLIC_KEY_ID,
      publicKeySpkiBase64: PUBLIC_KEY_SPKI_BASE64
    }
  });
});

app.post("/api/org/login", orgLoginLimiter, requireCsrf, (req, res) => {
  const parsed = orgLoginSchema.safeParse(req.body);
  if (!parsed.success) {
    addRisk(req, 3, "org_login_invalid_payload");
    apiError(res, 400, "Dados de login invalidos.");
    return;
  }

  const { userNumber, password } = parsed.data;
  const store = readOrgStore();
  const user = store.users.find((item) => item.userNumber === userNumber && item.status === "active");

  if (!user || !verifyPassword(password, user.passwordHash)) {
    addRisk(req, 6, "org_login_failed");
    audit("org.login_failed", req, {
      userNumberHash: createSha256Hex(`${APP_HMAC_SECRET}|org-user|${userNumber}`)
    });
    apiError(res, 401, "Credenciais invalidas.");
    return;
  }

  if (!user.emailVerifiedAt) {
    const emailDeliveryConfigured = hasEmailDeliveryConfigured();
    const debugOnlyDelivery = !emailDeliveryConfigured;
    if (!emailDeliveryConfigured && !ORG_SHOW_DELIVERY_DEBUG) {
      addRisk(req, 2, "org_login_email_delivery_unconfigured");
      apiError(
        res,
        503,
        "Canal de e-mail indisponivel no momento. Configure ORG_EMAIL_PROVIDER + ORG_RESEND_API_KEY ou ORG_EMAIL_WEBHOOK_URL."
      );
      return;
    }

    const now = Date.now();
    const verificationId = crypto.randomUUID();
    const verificationCode = createNumericToken(6);
    const verificationCodeHash = createSha256Hex(
      `${APP_HMAC_SECRET}|org-login-email|${verificationId}|${verificationCode}`
    );
    const expiresAt = new Date(now + 12 * 60 * 1000).toISOString();

    const challengeResult = updateOrgStore((mutableStore) => {
      mutableStore.emailVerifications = Array.isArray(mutableStore.emailVerifications)
        ? mutableStore.emailVerifications
        : [];

      mutableStore.emailVerifications = mutableStore.emailVerifications.filter((item) => {
        if (!item) {
          return false;
        }

        if (item.consumedAt) {
          const consumedAt = new Date(item.consumedAt).getTime();
          return Number.isFinite(consumedAt) && consumedAt > now - 24 * 60 * 60 * 1000;
        }

        const challengeExpiresAt = new Date(item.expiresAt || "").getTime();
        return Number.isFinite(challengeExpiresAt) && challengeExpiresAt > now;
      });

      mutableStore.emailVerifications = mutableStore.emailVerifications.filter((item) => {
        return !(item.userId === user.id && item.type === "login" && item.consumedAt === null);
      });

      mutableStore.emailVerifications.push({
        id: verificationId,
        type: "login",
        userId: user.id,
        userNumber: user.userNumber,
        email: user.email,
        newEmail: "",
        codeHash: verificationCodeHash,
        createdAt: new Date(now).toISOString(),
        expiresAt,
        consumedAt: null
      });

      return { ok: true };
    });

    if (!challengeResult.ok) {
      apiError(res, 500, "Nao foi possivel iniciar verificacao de e-mail.");
      return;
    }

    const loginVerificationMessage =
      `Codigo de confirmacao Fatality: ${verificationCode}. Valido por 12 minutos. ` +
      "Digite este codigo para concluir seu login no painel da organizacao.";

    enqueueOrgDelivery("email", user.email, loginVerificationMessage, {
      type: "login_email_verification",
      verificationId,
      userNumber: user.userNumber,
      role: user.role
    });

    clearRisk(req);
    audit("org.login_email_verification_sent", req, {
      userNumber: user.userNumber,
      role: user.role
    });

    res.status(202).json({
      ok: true,
      requiresEmailVerification: true,
      verificationId,
      email: user.email,
      deliveryMode: debugOnlyDelivery ? "debug_only" : "email",
      message: debugOnlyDelivery
        ? "Canal de e-mail nao configurado. Use o codigo de debug para concluir o login."
        : "Digite o codigo enviado para seu e-mail para concluir o login.",
      ...(debugOnlyDelivery
        ? {
            deliveryWarning:
              "Configure ORG_EMAIL_PROVIDER + ORG_RESEND_API_KEY ou ORG_EMAIL_WEBHOOK_URL para envio real de e-mail."
          }
        : {}),
      ...(ORG_SHOW_DELIVERY_DEBUG ? { debugVerificationCode: verificationCode } : {})
    });
    return;
  }

  const sessionId = createOrgSession(req, user);
  setOrgSessionCookie(res, sessionId);
  clearRisk(req);
  audit("org.login_success", req, { userNumber: user.userNumber, role: user.role });

  res.json({
    ok: true,
    session: buildOrgSessionResponse(orgSessions.get(sessionId))
  });
});

app.post("/api/org/login/confirm-email", orgWriteLimiter, requireCsrf, (req, res) => {
  const parsed = orgRegisterEmailConfirmSchema.safeParse(req.body);
  if (!parsed.success) {
    addRisk(req, 3, "org_login_confirm_invalid_payload");
    apiError(res, 400, "Dados de confirmacao de e-mail invalidos.");
    return;
  }

  const { verificationId, code } = parsed.data;
  const codeHash = createSha256Hex(`${APP_HMAC_SECRET}|org-login-email|${verificationId}|${code}`);
  const now = Date.now();
  let verifiedUser = null;

  const result = updateOrgStore((store) => {
    store.emailVerifications = Array.isArray(store.emailVerifications) ? store.emailVerifications : [];

    const verificationEntry = store.emailVerifications.find(
      (item) => item.id === verificationId && item.type === "login" && item.consumedAt === null
    );
    if (!verificationEntry) {
      return { error: "Codigo invalido ou expirado." };
    }

    if (new Date(verificationEntry.expiresAt || "").getTime() <= now) {
      return { error: "Codigo expirado. Realize o login novamente para gerar outro codigo." };
    }

    if (!safeStringEquals(codeHash, verificationEntry.codeHash)) {
      return { error: "Codigo de verificacao invalido." };
    }

    const user = store.users.find(
      (item) => item.id === verificationEntry.userId && item.status === "active"
    );
    if (!user) {
      return { error: "Usuario nao encontrado para esta verificacao." };
    }

    const nowIso = new Date(now).toISOString();
    verificationEntry.consumedAt = nowIso;
    user.emailVerifiedAt = nowIso;
    user.updatedAt = nowIso;
    verifiedUser = user;
    return { ok: true };
  });

  if (!result.ok || !verifiedUser) {
    addRisk(req, 2, "org_login_confirm_failed");
    apiError(res, 400, result.error || "Nao foi possivel confirmar o e-mail.");
    return;
  }

  const sessionId = createOrgSession(req, verifiedUser);
  setOrgSessionCookie(res, sessionId);
  clearRisk(req);
  audit("org.login_success", req, { userNumber: verifiedUser.userNumber, role: verifiedUser.role });
  audit("org.login_email_verified", req, { userNumber: verifiedUser.userNumber, role: verifiedUser.role });

  res.json({
    ok: true,
    session: buildOrgSessionResponse(orgSessions.get(sessionId))
  });
});

app.post("/api/org/logout", requireCsrf, requireOrgSession, (req, res) => {
  orgSessions.delete(req.orgSession.sessionId);
  clearOrgSessionCookie(res);
  audit("org.logout", req, { userNumber: req.orgSession.userNumber, role: req.orgSession.role });
  res.json({ ok: true });
});

app.get("/api/org/session", requireOrgSession, (req, res) => {
  res.json({
    ok: true,
    session: buildOrgSessionResponse(req.orgSession)
  });
});

app.get("/api/org/panel/full-data", requireOrgSession, (req, res) => {
  const store = readOrgStore();
  const canSeeTemporaryPassword = ORG_APPROVAL_ROLES.includes(String(req.orgSession.role || ""));
  const currentUser = store.users.find(
    (item) => item.userNumber === req.orgSession.userNumber && item.status === "active"
  );

  const users = store.users
    .map((item) => ({
      userNumber: item.userNumber,
      credentialNumber: item.userNumber,
      fullName: item.fullName || "",
      username: item.username || "",
      inGameName: item.inGameName || "",
      gameId: item.gameId || "",
      serverId: item.serverId || "",
      email: item.email || "",
      whatsapp: item.whatsapp || "",
      identificacaoGenero: item.identificacaoGenero || "Prefiro nao informar",
      note: item.note || "",
      role: item.role,
      status: item.status,
      mustChangePassword: !!item.mustChangePassword,
      emailVerifiedAt: item.emailVerifiedAt || null,
      approvedAt: item.approvedAt || null,
      approvedBy: item.approvedBy || null,
      createdAt: item.createdAt || null,
      updatedAt: item.updatedAt || null,
      temporaryPassword: canSeeTemporaryPassword ? item.temporaryPassword || null : null,
      temporaryPasswordUpdatedAt: canSeeTemporaryPassword ? item.temporaryPasswordUpdatedAt || null : null
    }))
    .sort((left, right) => String(left.credentialNumber).localeCompare(String(right.credentialNumber)));

  const requests = store.requests
    .map((item) => ({
      id: item.id,
      createdAt: item.createdAt || null,
      fullName: item.fullName || "",
      inGameName: item.inGameName || "",
      gameId: item.gameId || "",
      serverId: item.serverId || "",
      email: item.email || "",
      desiredRole: item.desiredRole || "player",
      identificacaoGenero: item.identificacaoGenero || "Prefiro nao informar",
      note: item.note || "",
      emailVerifiedAt: item.emailVerifiedAt || null,
      status: item.status || "pending",
      reviewedAt: item.reviewedAt || null,
      reviewedBy: item.reviewedBy || null,
      decisionReason: item.decisionReason || "",
      finalRole: item.finalRole || null,
      userNumber: item.userNumber || null
    }))
    .sort((left, right) => String(right.createdAt || "").localeCompare(String(left.createdAt || "")))
    .slice(0, 300);

  const preRegistrations = (Array.isArray(store.preRegistrations) ? store.preRegistrations : [])
    .map((item) => ({
      id: item.id,
      submissionId: item.submissionId || null,
      createdAt: item.createdAt || null,
      status: item.status || "pending",
      source: item.source || "recruitment_form",
      jogo: item.jogo || "Mobile Legends",
      nomeCompleto: item.nomeCompleto || "",
      nickInGame: item.nickInGame || "",
      eloMaximo: item.eloMaximo || "",
      wrRanked: item.wrRanked ?? null,
      maximoEstrelas: item.maximoEstrelas ?? null,
      rotaPrincipal: item.rotaPrincipal || "",
      horarioDisponivel: item.horarioDisponivel || "",
      identificacaoGenero: item.identificacaoGenero || "Prefiro nao informar",
      discord: item.discord || "",
      idJogo: item.idJogo || "",
      serverJogo: item.serverJogo || "",
      whatsapp: item.whatsapp || "",
      enviadoEm: item.enviadoEm || null
    }))
    .sort((left, right) => String(right.createdAt || "").localeCompare(String(left.createdAt || "")))
    .slice(0, 400);

  const me = currentUser
    ? {
        userNumber: currentUser.userNumber,
        credentialNumber: currentUser.userNumber,
        fullName: currentUser.fullName || "",
        username: currentUser.username || "",
        inGameName: currentUser.inGameName || "",
        gameId: currentUser.gameId || "",
        serverId: currentUser.serverId || "",
        email: currentUser.email || "",
        whatsapp: currentUser.whatsapp || "",
        identificacaoGenero: currentUser.identificacaoGenero || "Prefiro nao informar",
        note: currentUser.note || "",
        role: currentUser.role,
        status: currentUser.status,
        mustChangePassword: !!currentUser.mustChangePassword,
        emailVerifiedAt: currentUser.emailVerifiedAt || null,
        approvedAt: currentUser.approvedAt || null,
        approvedBy: currentUser.approvedBy || null,
        createdAt: currentUser.createdAt || null,
        updatedAt: currentUser.updatedAt || null,
        temporaryPassword: canSeeTemporaryPassword ? currentUser.temporaryPassword || null : null,
        temporaryPasswordUpdatedAt: canSeeTemporaryPassword
          ? currentUser.temporaryPasswordUpdatedAt || null
          : null
      }
    : null;

  res.json({
    ok: true,
    me,
    users,
    requests,
    preRegistrations
  });
});

function sendSseEvent(res, eventName, payload) {
  res.write(`event: ${eventName}\n`);
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function broadcastPerformanceUpdate(payload) {
  for (const client of performanceEventClients) {
    if (!client || !client.res) {
      performanceEventClients.delete(client);
      continue;
    }

    const role = String(client.role || "");
    const userNumber = String(client.userNumber || "");
    const targetPlayer = String(payload?.playerUserNumber || "");

    if (role === ORG_PLAYER_ROLE && targetPlayer && userNumber !== targetPlayer) {
      continue;
    }

    try {
      sendSseEvent(client.res, "performance_update", payload);
    } catch {
      performanceEventClients.delete(client);
    }
  }
}

app.get("/api/org/performance/events", requireOrgSession, (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no"
  });

  res.write(": ready\n\n");
  sendSseEvent(res, "performance_ready", {
    ok: true,
    userNumber: req.orgSession.userNumber,
    role: req.orgSession.role,
    week: getIsoWeekKey(new Date())
  });

  const client = {
    res,
    userNumber: req.orgSession.userNumber,
    role: req.orgSession.role
  };
  performanceEventClients.add(client);

  const keepAlive = setInterval(() => {
    try {
      res.write(": ping\n\n");
    } catch {
      // Ignore, close handler will cleanup.
    }
  }, 25 * 1000);

  req.on("close", () => {
    clearInterval(keepAlive);
    performanceEventClients.delete(client);
  });
});

app.get("/api/org/performance/board", requireOrgSession, (req, res) => {
  const store = readOrgStore();
  const role = String(req.orgSession.role || "");
  const week = getIsoWeekKey(new Date());

  if (role === ORG_PLAYER_ROLE) {
    const user = store.users.find(
      (item) => item.userNumber === req.orgSession.userNumber && item.status === "active"
    );
    if (!user) {
      apiError(res, 404, "Usuario nao encontrado.");
      return;
    }

    const summary = computePerformanceSummary(store, user.userNumber);
    const ranking = store.users
      .filter((item) => item && item.status === "active" && item.role === ORG_PLAYER_ROLE)
      .map((item) => {
        const rankSummary = computePerformanceSummary(store, item.userNumber);
        const currentWeekPercent =
          rankSummary.currentWeekPercent === null || rankSummary.currentWeekPercent === undefined
            ? null
            : Number(rankSummary.currentWeekPercent);
        const overallPercent = Number(rankSummary.overallPercent || 0);
        return {
          userNumber: item.userNumber,
          overallPercent,
          currentWeekPercent,
          rankScore: currentWeekPercent === null ? overallPercent : currentWeekPercent
        };
      })
      .sort((left, right) => {
        const scoreDiff = Number(right.rankScore || 0) - Number(left.rankScore || 0);
        if (Math.abs(scoreDiff) > 0.0001) {
          return scoreDiff;
        }

        const overallDiff = Number(right.overallPercent || 0) - Number(left.overallPercent || 0);
        if (Math.abs(overallDiff) > 0.0001) {
          return overallDiff;
        }

        return String(left.userNumber || "").localeCompare(String(right.userNumber || ""));
      });

    const rankingIndex = ranking.findIndex((item) => item.userNumber === user.userNumber);
    const rankingLeader = ranking.length > 0 ? ranking[0] : null;
    res.json({
      ok: true,
      mode: "player",
      week,
      player: {
        userNumber: user.userNumber,
        fullName: user.fullName || "",
        inGameName: user.inGameName || ""
      },
      summary: {
        ...summary,
        strengths: [],
        improvements: [],
        contributors: []
      },
      playerRanking: {
        position: rankingIndex >= 0 ? rankingIndex + 1 : null,
        totalPlayers: ranking.length,
        overallPercent: summary.overallPercent,
        currentWeekPercent: summary.currentWeekPercent,
        leaderPercent: rankingLeader ? rankingLeader.rankScore : null
      }
    });
    return;
  }

  const players = store.users
    .filter((item) => item && item.status === "active" && item.role === ORG_PLAYER_ROLE)
    .map((item) => ({
      userNumber: item.userNumber,
      fullName: item.fullName || "",
      inGameName: item.inGameName || ""
    }))
    .sort((a, b) => String(a.userNumber).localeCompare(String(b.userNumber)));

  const summaries = players.map((player) => {
    const summary = computePerformanceSummary(store, player.userNumber);
    return {
      playerUserNumber: player.userNumber,
      overallPercent: summary.overallPercent,
      currentWeekPercent: summary.currentWeekPercent,
      lastUpdatedAt: summary.lastUpdatedAt
    };
  });

  res.json({
    ok: true,
    mode: "editor",
    week,
    players,
    summaries
  });
});

app.get("/api/org/performance/player/:userNumber", requireOrgSession, (req, res) => {
  const targetUserNumber = String(req.params.userNumber || "").trim();
  if (!/^[0-9]{4,12}$/.test(targetUserNumber)) {
    apiError(res, 400, "Credencial do player invalida.");
    return;
  }

  const store = readOrgStore();
  const role = String(req.orgSession.role || "");

  if (role === ORG_PLAYER_ROLE && targetUserNumber !== req.orgSession.userNumber) {
    apiError(res, 403, "Acesso negado.");
    return;
  }

  const player = store.users.find(
    (item) => item.userNumber === targetUserNumber && item.status === "active"
  );
  if (!player || player.role !== ORG_PLAYER_ROLE) {
    apiError(res, 404, "Player nao encontrado.");
    return;
  }

  const summary = computePerformanceSummary(store, targetUserNumber);

  if (role === ORG_PLAYER_ROLE) {
    res.json({
      ok: true,
      week: summary.week,
      player: {
        userNumber: player.userNumber,
        fullName: player.fullName || "",
        inGameName: player.inGameName || ""
      },
      summary: {
        ...summary,
        strengths: [],
        improvements: [],
        contributors: []
      }
    });
    return;
  }

  const updates = (Array.isArray(store.performanceUpdates) ? store.performanceUpdates : [])
    .filter((item) => item && item.playerUserNumber === targetUserNumber)
    .sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || "")))
    .slice(0, 80)
    .map((item) => ({
      id: item.id,
      week: item.week,
      evaluatorUserNumber: item.evaluatorUserNumber,
      evaluatorRole: item.evaluatorRole,
      scores: item.scores,
      percent: computePercentFromScores(item.scores),
      strengths: normalizePerformanceBullets(item.strengths),
      improvements: normalizePerformanceBullets(item.improvements),
      note: item.note || "",
      createdAt: item.createdAt || null,
      updatedAt: item.updatedAt || null
    }));

  const myUpdateThisWeek = updates.find(
    (item) => item.week === summary.week && item.evaluatorUserNumber === req.orgSession.userNumber
  );

  res.json({
    ok: true,
    week: summary.week,
    player: {
      userNumber: player.userNumber,
      fullName: player.fullName || "",
      inGameName: player.inGameName || ""
    },
    summary,
    updates,
    myUpdateThisWeek: myUpdateThisWeek || null
  });
});

app.post(
  "/api/org/performance/updates",
  orgWriteLimiter,
  requireCsrf,
  requireOrgSession,
  requireOrgRole(ORG_PERFORMANCE_EDITOR_ROLES),
  (req, res) => {
    const parsed = orgPerformanceUpdateSchema.safeParse(req.body);
    if (!parsed.success) {
      apiError(res, 400, "Dados de desempenho invalidos.");
      return;
    }

    const actorUserNumber = req.orgSession.userNumber;
    const playerUserNumber = parsed.data.playerUserNumber;
    const week = parsed.data.week || getIsoWeekKey(new Date());
    const nowIso = new Date().toISOString();

    const result = updateOrgStore((store) => {
      store.performanceUpdates = Array.isArray(store.performanceUpdates) ? store.performanceUpdates : [];

      const player = store.users.find(
        (item) => item.userNumber === playerUserNumber && item.status === "active"
      );
      if (!player || player.role !== ORG_PLAYER_ROLE) {
        return { error: "Player nao encontrado." };
      }

      const existing = store.performanceUpdates.find(
        (item) =>
          item &&
          item.playerUserNumber === playerUserNumber &&
          item.week === week &&
          item.evaluatorUserNumber === actorUserNumber
      );

      const scores = {};
      for (const key of ORG_PERFORMANCE_CATEGORY_KEYS) {
        scores[key] = clampNumber(parsed.data.scores?.[key], 0, 10);
      }

      const strengths = normalizePerformanceBullets(parsed.data.strengths);
      const improvements = normalizePerformanceBullets(parsed.data.improvements);

      if (existing) {
        existing.evaluatorRole = String(req.orgSession.role || "");
        existing.scores = scores;
        existing.strengths = strengths;
        existing.improvements = improvements;
        existing.note = parsed.data.note || "";
        existing.updatedAt = nowIso;
        return { ok: true, created: false, updateId: existing.id, week, playerUserNumber };
      }

      const entry = {
        id: crypto.randomUUID(),
        playerUserNumber,
        evaluatorUserNumber: actorUserNumber,
        evaluatorRole: String(req.orgSession.role || ""),
        week,
        scores,
        strengths,
        improvements,
        note: parsed.data.note || "",
        createdAt: nowIso,
        updatedAt: nowIso
      };

      store.performanceUpdates.push(entry);
      return { ok: true, created: true, updateId: entry.id, week, playerUserNumber };
    });

    if (!result.ok) {
      apiError(res, 400, result.error || "Falha ao salvar desempenho.");
      return;
    }

    const store = readOrgStore();
    const summary = computePerformanceSummary(store, playerUserNumber, week);
    audit("org.performance_update_saved", req, {
      actor: actorUserNumber,
      playerUserNumber,
      week,
      updateId: result.updateId
    });

    broadcastPerformanceUpdate({
      playerUserNumber,
      week,
      updatedAt: nowIso
    });

    res.json({
      ok: true,
      created: !!result.created,
      updateId: result.updateId,
      playerUserNumber,
      week,
      summary
    });
  }
);

app.post("/api/org/password/change", orgWriteLimiter, requireCsrf, requireOrgSession, (req, res) => {
  const parsed = orgChangePasswordSchema.safeParse(req.body);
  if (!parsed.success) {
    apiError(res, 400, "Dados de troca de senha invalidos.");
    return;
  }

  const { currentPassword, newPassword } = parsed.data;
  const userNumber = req.orgSession.userNumber;

  const result = updateOrgStore((store) => {
    const user = store.users.find((item) => item.userNumber === userNumber && item.status === "active");
    if (!user) {
      return { error: "Usuario nao encontrado." };
    }

    if (!verifyPassword(currentPassword, user.passwordHash)) {
      return { error: "Senha atual incorreta." };
    }

    user.passwordHash = createPasswordHash(newPassword);
    user.mustChangePassword = false;
    user.updatedAt = new Date().toISOString();
    user.temporaryPassword = "";
    user.temporaryPasswordUpdatedAt = user.updatedAt;
    return { ok: true };
  });

  if (!result.ok) {
    addRisk(req, 3, "org_change_password_failed");
    apiError(res, 400, result.error || "Nao foi possivel trocar a senha.");
    return;
  }

  audit("org.password_changed", req, { userNumber });
  res.json({ ok: true, message: "Senha atualizada com sucesso." });
});

app.post("/api/org/email/change/request", orgWriteLimiter, requireCsrf, requireOrgSession, (req, res) => {
  const parsed = orgEmailChangeRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    apiError(res, 400, "Dados de troca de e-mail invalidos.");
    return;
  }

  const { currentPassword, newEmail, newEmailConfirm } = parsed.data;
  if (!safeStringEquals(newEmail, newEmailConfirm)) {
    apiError(res, 400, "E-mail e confirmacao de e-mail devem ser iguais.");
    return;
  }

  const emailDeliveryConfigured = hasEmailDeliveryConfigured();
  const debugOnlyDelivery = !emailDeliveryConfigured;
  if (!emailDeliveryConfigured && !ORG_SHOW_DELIVERY_DEBUG) {
    addRisk(req, 2, "org_email_change_delivery_unconfigured");
    apiError(
      res,
      503,
      "Canal de e-mail indisponivel no momento. Configure ORG_EMAIL_PROVIDER + ORG_RESEND_API_KEY ou ORG_EMAIL_WEBHOOK_URL."
    );
    return;
  }

  const now = Date.now();
  const verificationId = crypto.randomUUID();
  const verificationCode = createNumericToken(6);
  const verificationCodeHash = createSha256Hex(
    `${APP_HMAC_SECRET}|org-email-change|${verificationId}|${verificationCode}`
  );
  const expiresAt = new Date(now + 12 * 60 * 1000).toISOString();
  let currentEmail = "";

  const result = updateOrgStore((store) => {
    store.emailVerifications = Array.isArray(store.emailVerifications) ? store.emailVerifications : [];
    store.emailVerifications = store.emailVerifications.filter((item) => {
      if (!item) {
        return false;
      }

      if (item.consumedAt) {
        const consumedAt = new Date(item.consumedAt).getTime();
        return Number.isFinite(consumedAt) && consumedAt > now - 24 * 60 * 60 * 1000;
      }

      const challengeExpiresAt = new Date(item.expiresAt || "").getTime();
      return Number.isFinite(challengeExpiresAt) && challengeExpiresAt > now;
    });

    const user = store.users.find(
      (item) => item.userNumber === req.orgSession.userNumber && item.status === "active"
    );
    if (!user) {
      return { error: "Usuario nao encontrado." };
    }

    if (!verifyPassword(currentPassword, user.passwordHash)) {
      return { error: "Senha atual incorreta." };
    }

    if (safeStringEquals(user.email, newEmail)) {
      return { error: "Informe um e-mail diferente do atual." };
    }

    const hasEmailInUse = store.users.some(
      (item) => item.status === "active" && item.id !== user.id && safeStringEquals(item.email, newEmail)
    );
    if (hasEmailInUse) {
      return { error: "Este e-mail ja esta em uso por outra conta ativa." };
    }

    store.emailVerifications = store.emailVerifications.filter((item) => {
      return !(item.userId === user.id && item.type === "email_change" && item.consumedAt === null);
    });

    store.emailVerifications.push({
      id: verificationId,
      type: "email_change",
      userId: user.id,
      userNumber: user.userNumber,
      email: newEmail,
      newEmail,
      codeHash: verificationCodeHash,
      createdAt: new Date(now).toISOString(),
      expiresAt,
      consumedAt: null
    });

    currentEmail = user.email;
    return { ok: true };
  });

  if (!result.ok) {
    addRisk(req, 2, "org_email_change_request_failed");
    apiError(res, 400, result.error || "Nao foi possivel iniciar troca de e-mail.");
    return;
  }

  const message =
    `Codigo de confirmacao Fatality: ${verificationCode}. Valido por 12 minutos. ` +
    "Digite este codigo para confirmar a troca de e-mail da sua conta.";

  enqueueOrgDelivery("email", newEmail, message, {
    type: "email_change_verification",
    verificationId,
    userNumber: req.orgSession.userNumber
  });

  audit("org.email_change_requested", req, {
    userNumber: req.orgSession.userNumber,
    fromEmailHash: createSha256Hex(`${APP_HMAC_SECRET}|org-email|${currentEmail}`),
    toEmailHash: createSha256Hex(`${APP_HMAC_SECRET}|org-email|${newEmail}`)
  });

  res.status(202).json({
    ok: true,
    verificationId,
    deliveryMode: debugOnlyDelivery ? "debug_only" : "email",
    message: debugOnlyDelivery
      ? "Canal de e-mail nao configurado. Use o codigo de debug para concluir a troca."
      : "Codigo enviado para o novo e-mail. Confirme para concluir a troca.",
    ...(debugOnlyDelivery
      ? {
          deliveryWarning:
            "Configure ORG_EMAIL_PROVIDER + ORG_RESEND_API_KEY ou ORG_EMAIL_WEBHOOK_URL para envio real de e-mail."
        }
      : {}),
    ...(ORG_SHOW_DELIVERY_DEBUG ? { debugVerificationCode: verificationCode } : {})
  });
});

app.post("/api/org/email/change/confirm", orgWriteLimiter, requireCsrf, requireOrgSession, (req, res) => {
  const parsed = orgRegisterEmailConfirmSchema.safeParse(req.body);
  if (!parsed.success) {
    apiError(res, 400, "Dados de confirmacao invalidos.");
    return;
  }

  const { verificationId, code } = parsed.data;
  const codeHash = createSha256Hex(`${APP_HMAC_SECRET}|org-email-change|${verificationId}|${code}`);
  const now = Date.now();
  let updatedUser = null;
  let oldEmail = "";

  const result = updateOrgStore((store) => {
    store.emailVerifications = Array.isArray(store.emailVerifications) ? store.emailVerifications : [];

    const verificationEntry = store.emailVerifications.find(
      (item) =>
        item.id === verificationId &&
        item.type === "email_change" &&
        item.consumedAt === null &&
        item.userId === req.orgSession.userId
    );
    if (!verificationEntry) {
      return { error: "Codigo invalido ou expirado." };
    }

    if (new Date(verificationEntry.expiresAt || "").getTime() <= now) {
      return { error: "Codigo expirado. Solicite nova troca de e-mail." };
    }

    if (!safeStringEquals(codeHash, verificationEntry.codeHash)) {
      return { error: "Codigo de verificacao invalido." };
    }

    const user = store.users.find(
      (item) => item.id === verificationEntry.userId && item.status === "active"
    );
    if (!user) {
      return { error: "Usuario nao encontrado." };
    }

    const targetEmail = String(verificationEntry.newEmail || verificationEntry.email || "").toLowerCase();
    if (!targetEmail) {
      return { error: "Dados de troca de e-mail invalidos." };
    }

    const hasEmailInUse = store.users.some(
      (item) => item.status === "active" && item.id !== user.id && safeStringEquals(item.email, targetEmail)
    );
    if (hasEmailInUse) {
      return { error: "Este e-mail ja esta em uso por outra conta ativa." };
    }

    const nowIso = new Date(now).toISOString();
    oldEmail = user.email;
    user.email = targetEmail;
    user.emailVerifiedAt = nowIso;
    user.updatedAt = nowIso;
    verificationEntry.consumedAt = nowIso;
    updatedUser = user;
    return { ok: true };
  });

  if (!result.ok || !updatedUser) {
    addRisk(req, 2, "org_email_change_confirm_failed");
    apiError(res, 400, result.error || "Nao foi possivel confirmar troca de e-mail.");
    return;
  }

  req.orgSession.email = updatedUser.email;
  req.orgSession.emailVerifiedAt = updatedUser.emailVerifiedAt || null;

  enqueueOrgDelivery(
    "email",
    oldEmail,
    "Seu e-mail de acesso na Fatality foi alterado. Se nao foi voce, contacte a lideranca imediatamente.",
    {
      type: "email_changed_notice",
      userNumber: updatedUser.userNumber
    }
  );

  audit("org.email_changed", req, {
    userNumber: updatedUser.userNumber,
    fromEmailHash: createSha256Hex(`${APP_HMAC_SECRET}|org-email|${oldEmail}`),
    toEmailHash: createSha256Hex(`${APP_HMAC_SECRET}|org-email|${updatedUser.email}`)
  });

  res.json({
    ok: true,
    message: "E-mail atualizado com sucesso.",
    session: buildOrgSessionResponse(req.orgSession)
  });
});

app.post("/api/org/register-request", orgWriteLimiter, requireCsrf, (req, res) => {
  apiError(
    res,
    410,
    "Fluxo de cadastro por solicitacao foi desativado. Use o cadastro direto no painel (dono, lider, vice-lider e ADM)."
  );
  return;

  const parsed = orgRegistrationRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    addRisk(req, 3, "org_register_invalid_payload");
    apiError(res, 400, "Dados de cadastro invalidos.");
    return;
  }

  const payload = parsed.data;
  let createdRequest = null;

  const result = updateOrgStore((store) => {
    const hasUserWithEmail = store.users.some(
      (item) => item.email === payload.email && item.status === "active"
    );
    const hasPendingSameEmail = store.requests.some(
      (item) => item.status === "pending" && item.email === payload.email
    );

    if (hasUserWithEmail || hasPendingSameEmail) {
      return { error: "Ja existe cadastro pendente ou ativo para esses dados." };
    }

    const requestCreatedAt = new Date().toISOString();
    const requestId = crypto.randomUUID();
    createdRequest = {
      requestId,
      email: payload.email,
      desiredRole: payload.desiredRole,
      identificacaoGenero: payload.identificacaoGenero
    };

    store.requests.push({
      id: requestId,
      createdAt: requestCreatedAt,
      fullName: payload.fullName,
      inGameName: payload.inGameName,
      gameId: payload.gameId,
      serverId: payload.serverId,
      email: payload.email,
      desiredRole: payload.desiredRole,
      identificacaoGenero: payload.identificacaoGenero,
      note: payload.note,
      emailVerifiedAt: null,
      status: "pending",
      reviewedAt: null,
      reviewedBy: null,
      decisionReason: ""
    });

    return { requestId };
  });

  if (!result.ok || !createdRequest) {
    addRisk(req, 2, "org_register_conflict");
    apiError(res, 409, result.error || "Conflito no cadastro.");
    return;
  }

  audit("org.request_created", req, {
    requestId: createdRequest.requestId,
    emailHash: createSha256Hex(`${APP_HMAC_SECRET}|org-email|${createdRequest.email}`),
    desiredRole: createdRequest.desiredRole,
    identificacaoGenero: createdRequest.identificacaoGenero
  });

  res.status(202).json({
    ok: true,
    requestId: createdRequest.requestId,
    message: "Cadastro enviado para aprovacao da lideranca."
  });
});

app.post("/api/org/register-request/confirm-email", orgWriteLimiter, requireCsrf, (req, res) => {
  apiError(
    res,
    410,
    "Confirmacao de cadastro por e-mail foi desativada. Use o cadastro direto no painel (dono, lider, vice-lider e ADM)."
  );
  return;

  const parsed = orgRegisterEmailConfirmSchema.safeParse(req.body);
  if (!parsed.success) {
    addRisk(req, 3, "org_register_confirm_invalid_payload");
    apiError(res, 400, "Dados de confirmacao de e-mail invalidos.");
    return;
  }

  const { verificationId, code } = parsed.data;
  const codeHash = createSha256Hex(`${APP_HMAC_SECRET}|org-register-email|${verificationId}|${code}`);
  const now = Date.now();
  let createdRequest = null;

  const result = updateOrgStore((store) => {
    const verificationEntry = store.registrationVerifications.find(
      (item) => item.id === verificationId && item.consumedAt === null
    );
    if (!verificationEntry) {
      return { error: "Codigo invalido ou expirado." };
    }

    if (new Date(verificationEntry.expiresAt).getTime() <= now) {
      return { error: "Codigo expirado. Solicite novo cadastro." };
    }

    if (!safeStringEquals(codeHash, verificationEntry.codeHash)) {
      return { error: "Codigo de verificacao invalido." };
    }

    const email = String(verificationEntry.email || "").toLowerCase();
    const hasUserWithEmail = store.users.some(
      (item) => item.email === email && item.status === "active"
    );
    const hasPendingSameEmail = store.requests.some(
      (item) => item.status === "pending" && item.email === email
    );

    if (hasUserWithEmail || hasPendingSameEmail) {
      return { error: "Ja existe cadastro pendente ou ativo para este e-mail." };
    }

    const requestId = crypto.randomUUID();
    const requestCreatedAt = new Date().toISOString();
    createdRequest = {
      requestId,
      email
    };

    store.requests.push({
      id: requestId,
      createdAt: requestCreatedAt,
      fullName: verificationEntry.fullName,
      inGameName: verificationEntry.inGameName,
      gameId: verificationEntry.gameId,
      serverId: verificationEntry.serverId,
      email,
      desiredRole: verificationEntry.desiredRole,
      identificacaoGenero: verificationEntry.identificacaoGenero || "Prefiro nao informar",
      note: verificationEntry.note || "",
      emailVerifiedAt: requestCreatedAt,
      status: "pending",
      reviewedAt: null,
      reviewedBy: null,
      decisionReason: ""
    });

    verificationEntry.consumedAt = requestCreatedAt;
    store.registrationVerifications = store.registrationVerifications.filter((item) => {
      return item.email !== email;
    });
    return { requestId };
  });

  if (!result.ok || !createdRequest) {
    addRisk(req, 2, "org_register_confirm_conflict");
    apiError(res, 409, result.error || "Nao foi possivel concluir a validacao de e-mail.");
    return;
  }

  audit("org.request_email_confirmed", req, {
    requestId: createdRequest.requestId,
    emailHash: createSha256Hex(`${APP_HMAC_SECRET}|org-email|${createdRequest.email}`)
  });

  res.json({
    ok: true,
    requestId: createdRequest.requestId,
    message: "Email validado. Cadastro enviado para aprovacao da lideranca."
  });
});

app.post("/api/org/password/request-reset", orgWriteLimiter, requireCsrf, (req, res) => {
  const parsed = orgResetRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    addRisk(req, 2, "org_reset_request_invalid_payload");
    apiError(res, 400, "Dados de recuperacao invalidos.");
    return;
  }

  const { userNumber, email, emailConfirm, newPassword } = parsed.data;
  if (!safeStringEquals(email, emailConfirm)) {
    addRisk(req, 2, "org_reset_email_confirmation_mismatch");
    apiError(res, 400, "Email e confirmacao de email devem ser iguais.");
    return;
  }

  let changedUser = null;

  updateOrgStore((store) => {
    const user = store.users.find(
      (item) =>
        item.userNumber === userNumber &&
        item.email === email &&
        item.status === "active"
    );

    if (!user) {
      return {};
    }

    user.passwordHash = createPasswordHash(newPassword);
    user.mustChangePassword = false;
    user.updatedAt = new Date().toISOString();
    user.temporaryPassword = "";
    user.temporaryPasswordUpdatedAt = user.updatedAt;
    changedUser = {
      userNumber: user.userNumber,
      role: user.role,
      email: user.email,
      whatsapp: user.whatsapp
    };
    return {};
  });

  if (changedUser) {
    const resetMessage =
      `Confirmacao Fatality: senha alterada com sucesso para a credencial ${changedUser.userNumber}.`;

    enqueueOrgDelivery("email", changedUser.email, resetMessage, {
      type: "password_reset_email_confirmed",
      userNumber: changedUser.userNumber
    });
    enqueueOrgDelivery("whatsapp", changedUser.whatsapp, resetMessage, {
      type: "password_reset_email_confirmed",
      userNumber: changedUser.userNumber
    });

    audit("org.password_reset_email_confirmed", req, {
      userNumber: changedUser.userNumber,
      role: changedUser.role
    });
  }

  res.json({
    ok: true,
    message: "Se os dados estiverem corretos e o e-mail confirmado, a senha foi atualizada."
  });
});

app.post("/api/org/password/confirm-reset", orgWriteLimiter, requireCsrf, (_req, res) => {
  apiError(res, 410, "Fluxo por token desativado. Use confirmacao de e-mail.");
});

app.get("/api/org/admin/requests", requireOrgSession, requireOrgRole(ORG_APPROVAL_ROLES), (req, res) => {
  const store = readOrgStore();
  const pending = store.requests
    .filter((item) => item.status === "pending")
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
    .slice(0, 60);

  res.json({
    ok: true,
    total: pending.length,
    items: pending
  });
});

app.post(
  "/api/org/admin/requests/:requestId/approve",
  orgWriteLimiter,
  requireCsrf,
  requireOrgSession,
  requireOrgRole(ORG_APPROVAL_ROLES),
  (req, res) => {
    const parsed = orgApproveSchema.safeParse(req.body || {});
    if (!parsed.success) {
      apiError(res, 400, "Dados de aprovacao invalidos.");
      return;
    }

    const requestId = String(req.params.requestId || "").trim();
    if (!requestId) {
      apiError(res, 400, "Solicitacao invalida.");
      return;
    }

    let createdUser = null;
    const temporaryPassword = createTemporaryPassword();

    const result = updateOrgStore((store) => {
      const requestEntry = store.requests.find((item) => item.id === requestId);
      if (!requestEntry || requestEntry.status !== "pending") {
        return { error: "Solicitacao nao encontrada ou ja analisada." };
      }

      const finalRole = parsed.data.finalRole || requestEntry.desiredRole;
      if (!ORG_ROLE_SET.has(finalRole)) {
        return { error: "Cargo final invalido." };
      }

      if (!canAssignOrgRole(req.orgSession.role, finalRole)) {
        return { error: "Seu cargo nao tem permissao para aprovar este nivel de acesso." };
      }

      const existingEmail = store.users.some(
        (item) => item.email === requestEntry.email && item.status === "active"
      );
      if (existingEmail) {
        return { error: "Ja existe usuario ativo com esses dados." };
      }

      const userNumber = allocateOrgUserNumber(store);
      const username = allocateOrgUsername(store, requestEntry.inGameName || requestEntry.fullName);
      createdUser = {
        id: crypto.randomUUID(),
        userNumber,
        fullName: requestEntry.fullName,
        username,
        inGameName: requestEntry.inGameName || "",
        gameId: requestEntry.gameId || "",
        serverId: requestEntry.serverId || "",
        identificacaoGenero: requestEntry.identificacaoGenero || "Prefiro nao informar",
        email: requestEntry.email,
        whatsapp: requestEntry.whatsapp || "",
        note: requestEntry.note || "",
        role: finalRole,
        status: "active",
        mustChangePassword: true,
        emailVerifiedAt: null,
        approvedAt: new Date().toISOString(),
        approvedBy: req.orgSession.userNumber,
        createdAt: requestEntry.createdAt,
        updatedAt: new Date().toISOString(),
        passwordHash: createPasswordHash(temporaryPassword),
        temporaryPassword,
        temporaryPasswordUpdatedAt: new Date().toISOString()
      };
      store.users.push(createdUser);

      requestEntry.status = "approved";
      requestEntry.reviewedAt = new Date().toISOString();
      requestEntry.reviewedBy = req.orgSession.userNumber;
      requestEntry.decisionReason = "";
      requestEntry.finalRole = finalRole;
      requestEntry.userNumber = userNumber;

      return { ok: true };
    });

    if (!result.ok || !createdUser) {
      apiError(res, 409, result.error || "Nao foi possivel aprovar o cadastro.");
      return;
    }

    const credentialsMessage =
      `Fatality acesso aprovado. Credencial: ${createdUser.userNumber}. Senha inicial: ${temporaryPassword}. ` +
      "Troque a senha no primeiro acesso.";

    if (String(createdUser.whatsapp || "").trim()) {
      enqueueOrgDelivery("whatsapp", createdUser.whatsapp, credentialsMessage, {
        type: "new_credentials",
        userNumber: createdUser.userNumber,
        role: createdUser.role
      });
    }
    enqueueOrgDelivery("email", createdUser.email, credentialsMessage, {
      type: "new_credentials",
      userNumber: createdUser.userNumber,
      role: createdUser.role
    });

    audit("org.request_approved", req, {
      requestId,
      userNumber: createdUser.userNumber,
      role: createdUser.role
    });

    res.json({
      ok: true,
      userNumber: createdUser.userNumber,
      role: createdUser.role,
      temporaryPassword
    });
  }
);

app.post(
  "/api/org/admin/requests/:requestId/reject",
  orgWriteLimiter,
  requireCsrf,
  requireOrgSession,
  requireOrgRole(ORG_APPROVAL_ROLES),
  (req, res) => {
    const parsed = orgRejectSchema.safeParse(req.body || {});
    if (!parsed.success) {
      apiError(res, 400, "Dados de rejeicao invalidos.");
      return;
    }

    const requestId = String(req.params.requestId || "").trim();
    const result = updateOrgStore((store) => {
      const requestEntry = store.requests.find((item) => item.id === requestId);
      if (!requestEntry || requestEntry.status !== "pending") {
        return { error: "Solicitacao nao encontrada ou ja analisada." };
      }

      requestEntry.status = "rejected";
      requestEntry.reviewedAt = new Date().toISOString();
      requestEntry.reviewedBy = req.orgSession.userNumber;
      requestEntry.decisionReason = parsed.data.reason || "";
      return { ok: true };
    });

    if (!result.ok) {
      apiError(res, 409, result.error || "Nao foi possivel rejeitar.");
      return;
    }

    audit("org.request_rejected", req, {
      requestId,
      reviewedBy: req.orgSession.userNumber
    });
    res.json({ ok: true });
  }
);

app.get("/api/org/admin/users", requireOrgSession, requireOrgRole(ORG_APPROVAL_ROLES), (req, res) => {
  const store = readOrgStore();
  const users = store.users
    .filter((item) => item.status === "active")
    .map((item) => ({
      userNumber: item.userNumber,
      credentialNumber: item.userNumber,
      fullName: item.fullName,
      username: item.username,
      inGameName: item.inGameName || "",
      gameId: item.gameId || "",
      serverId: item.serverId || "",
      whatsapp: item.whatsapp || "",
      identificacaoGenero: item.identificacaoGenero || "Prefiro nao informar",
      note: item.note || "",
      email: item.email || "",
      role: item.role,
      status: item.status,
      mustChangePassword: item.mustChangePassword,
      emailVerifiedAt: item.emailVerifiedAt || null,
      approvedAt: item.approvedAt,
      approvedBy: item.approvedBy || null,
      createdAt: item.createdAt || null,
      updatedAt: item.updatedAt || null,
      temporaryPassword: item.temporaryPassword || null,
      temporaryPasswordUpdatedAt: item.temporaryPasswordUpdatedAt || null
    }))
    .sort((left, right) => left.userNumber.localeCompare(right.userNumber));

  res.json({ ok: true, total: users.length, items: users });
});

app.post(
  "/api/org/admin/users/direct-create",
  orgWriteLimiter,
  requireCsrf,
  requireOrgSession,
  requireOrgRole(ORG_APPROVAL_ROLES),
  (req, res) => {
    const parsed = orgDirectCreateUserSchema.safeParse(req.body || {});
    if (!parsed.success) {
      apiError(res, 400, "Dados invalidos para cadastro direto.");
      return;
    }

    const payload = parsed.data;
    if (!canAssignOrgRole(req.orgSession.role, payload.role)) {
      apiError(res, 403, "Seu cargo nao tem permissao para criar esse nivel de acesso.");
      return;
    }

    const temporaryPassword = createTemporaryPassword();
    let createdUser = null;
    const createdAt = new Date().toISOString();

    const result = updateOrgStore((store) => {
      const emailInUse = store.users.some(
        (item) =>
          item.status === "active" &&
          safeStringEquals(String(item.email || "").toLowerCase(), String(payload.email || "").toLowerCase())
      );
      if (emailInUse) {
        return { error: "Ja existe membro ativo com este e-mail." };
      }

      const userNumber = allocateOrgUserNumber(store);
      const username = allocateOrgUsername(store, payload.inGameName || payload.fullName);
      createdUser = {
        id: crypto.randomUUID(),
        userNumber,
        fullName: payload.fullName,
        username,
        inGameName: payload.inGameName || "",
        gameId: payload.gameId || "",
        serverId: payload.serverId || "",
        identificacaoGenero: payload.identificacaoGenero || "Prefiro nao informar",
        email: payload.email,
        whatsapp: payload.whatsapp || "",
        note: payload.note || "",
        role: payload.role,
        status: "active",
        mustChangePassword: true,
        emailVerifiedAt: null,
        approvedAt: createdAt,
        approvedBy: req.orgSession.userNumber,
        createdAt,
        updatedAt: createdAt,
        passwordHash: createPasswordHash(temporaryPassword),
        temporaryPassword,
        temporaryPasswordUpdatedAt: createdAt
      };
      store.users.push(createdUser);

      store.requests.push({
        id: crypto.randomUUID(),
        createdAt,
        source: "direct_admin_create",
        fullName: payload.fullName,
        inGameName: payload.inGameName || "",
        gameId: payload.gameId || "",
        serverId: payload.serverId || "",
        email: payload.email,
        whatsapp: payload.whatsapp || "",
        desiredRole: payload.role,
        identificacaoGenero: payload.identificacaoGenero || "Prefiro nao informar",
        note: payload.note || "",
        emailVerifiedAt: null,
        status: "approved",
        reviewedAt: createdAt,
        reviewedBy: req.orgSession.userNumber,
        decisionReason: "Cadastro direto pelo painel interno.",
        finalRole: payload.role,
        userNumber
      });

      return { ok: true };
    });

    if (!result.ok || !createdUser) {
      apiError(res, 409, result.error || "Nao foi possivel criar o membro.");
      return;
    }

    const credentialsMessage =
      `Fatality cadastro interno aprovado. Credencial: ${createdUser.userNumber}. Senha provisoria: ${temporaryPassword}. ` +
      "Altere a senha no primeiro acesso.";
    enqueueOrgDelivery("email", createdUser.email, credentialsMessage, {
      type: "new_credentials",
      userNumber: createdUser.userNumber,
      role: createdUser.role
    });
    if (String(createdUser.whatsapp || "").trim()) {
      enqueueOrgDelivery("whatsapp", createdUser.whatsapp, credentialsMessage, {
        type: "new_credentials",
        userNumber: createdUser.userNumber,
        role: createdUser.role
      });
    }

    audit("org.user_direct_created", req, {
      actor: req.orgSession.userNumber,
      userNumber: createdUser.userNumber,
      role: createdUser.role
    });

    res.json({
      ok: true,
      userNumber: createdUser.userNumber,
      credentialNumber: createdUser.userNumber,
      role: createdUser.role,
      temporaryPassword
    });
  }
);

app.post(
  "/api/org/admin/users/:userNumber/remind-email-verification",
  orgWriteLimiter,
  requireCsrf,
  requireOrgSession,
  requireOrgRole(ORG_APPROVAL_ROLES),
  (req, res) => {
    const userNumber = String(req.params.userNumber || "").trim();
    if (!/^[0-9]{4,12}$/.test(userNumber)) {
      apiError(res, 400, "Credencial invalida.");
      return;
    }

    const store = readOrgStore();
    const user = store.users.find((item) => item.userNumber === userNumber && item.status === "active");
    if (!user) {
      apiError(res, 404, "Membro nao encontrado.");
      return;
    }

    if (user.emailVerifiedAt) {
      apiError(res, 409, "Este membro ja possui e-mail verificado.");
      return;
    }

    const message =
      `Lembrete Fatality: sua conta de credencial ${user.userNumber} ainda nao concluiu a verificacao de e-mail. ` +
      "Entre no painel e confirme o codigo enviado para o seu e-mail.";

    enqueueOrgDelivery("email", user.email, message, {
      type: "email_verification_reminder",
      userNumber: user.userNumber,
      role: user.role
    });

    if (String(user.whatsapp || "").trim()) {
      enqueueOrgDelivery("whatsapp", user.whatsapp, message, {
        type: "email_verification_reminder",
        userNumber: user.userNumber,
        role: user.role
      });
    }

    audit("org.email_verification_reminder_sent", req, {
      actor: req.orgSession.userNumber,
      target: user.userNumber,
      role: user.role
    });

    res.json({ ok: true, message: `Lembrete enviado para ${user.fullName}.` });
  }
);

app.post(
  "/api/org/admin/users/:userNumber/update-profile",
  orgWriteLimiter,
  requireCsrf,
  requireOrgSession,
  requireOrgRole(ORG_APPROVAL_ROLES),
  (req, res) => {
    const targetUserNumber = String(req.params.userNumber || "").trim();
    if (!/^[0-9]{4,12}$/.test(targetUserNumber)) {
      apiError(res, 400, "Credencial invalida.");
      return;
    }

    const parsed = orgUpdateUserProfileSchema.safeParse(req.body || {});
    if (!parsed.success) {
      apiError(res, 400, "Dados invalidos para atualizacao de cadastro.");
      return;
    }

    const payload = parsed.data;
    const nowIso = new Date().toISOString();
    let updatedUser = null;
    let previousEmail = "";
    let emailChanged = false;

    const result = updateOrgStore((store) => {
      const targetUser = store.users.find(
        (item) => item.userNumber === targetUserNumber && item.status === "active"
      );
      if (!targetUser) {
        return { error: "Membro nao encontrado.", statusCode: 404 };
      }

      if (!canAssignOrgRole(req.orgSession.role, targetUser.role)) {
        return { error: "Seu cargo nao tem permissao para atualizar este membro.", statusCode: 403 };
      }

      const emailInUse = store.users.some((item) => {
        return (
          item.status === "active" &&
          item.id !== targetUser.id &&
          safeStringEquals(String(item.email || "").toLowerCase(), payload.email)
        );
      });
      if (emailInUse) {
        return { error: "Ja existe membro ativo com este e-mail.", statusCode: 409 };
      }

      previousEmail = String(targetUser.email || "");
      emailChanged = !safeStringEquals(previousEmail.toLowerCase(), payload.email);

      targetUser.fullName = payload.fullName;
      targetUser.inGameName = payload.inGameName;
      targetUser.gameId = payload.gameId;
      targetUser.serverId = payload.serverId;
      targetUser.whatsapp = payload.whatsapp || "";
      targetUser.identificacaoGenero = payload.identificacaoGenero || "Prefiro nao informar";
      targetUser.note = payload.note || "";
      targetUser.email = payload.email;
      if (emailChanged) {
        targetUser.emailVerifiedAt = null;
      }
      targetUser.updatedAt = nowIso;

      updatedUser = targetUser;
      return { ok: true };
    });

    if (!result.ok || !updatedUser) {
      apiError(res, result.statusCode || 409, result.error || "Nao foi possivel atualizar cadastro.");
      return;
    }

    for (const session of orgSessions.values()) {
      if (session.userId === updatedUser.id) {
        session.email = updatedUser.email;
        session.emailVerifiedAt = updatedUser.emailVerifiedAt || null;
      }
    }

    if (safeStringEquals(req.orgSession.userNumber, updatedUser.userNumber)) {
      req.orgSession.email = updatedUser.email;
      req.orgSession.emailVerifiedAt = updatedUser.emailVerifiedAt || null;
    }

    const updateMessage =
      `Atualizacao Fatality: seu cadastro interno foi atualizado pela lideranca. ` +
      `Credencial: ${updatedUser.userNumber}.`;
    enqueueOrgDelivery("email", updatedUser.email, updateMessage, {
      type: "profile_updated_by_management",
      userNumber: updatedUser.userNumber
    });
    if (emailChanged && previousEmail && !safeStringEquals(previousEmail, updatedUser.email)) {
      enqueueOrgDelivery(
        "email",
        previousEmail,
        "Seu e-mail de cadastro da Fatality foi alterado. Se nao foi voce, contacte a lideranca imediatamente.",
        {
          type: "profile_email_changed_notice",
          userNumber: updatedUser.userNumber
        }
      );
    }

    if (String(updatedUser.whatsapp || "").trim()) {
      enqueueOrgDelivery("whatsapp", updatedUser.whatsapp, updateMessage, {
        type: "profile_updated_by_management",
        userNumber: updatedUser.userNumber
      });
    }

    audit("org.user_profile_updated", req, {
      actor: req.orgSession.userNumber,
      target: updatedUser.userNumber,
      role: updatedUser.role,
      emailChanged
    });

    res.json({
      ok: true,
      message: emailChanged
        ? "Cadastro atualizado. O e-mail foi alterado e voltou para pendente de verificacao."
        : "Cadastro atualizado com sucesso.",
      user: {
        userNumber: updatedUser.userNumber,
        credentialNumber: updatedUser.userNumber,
        fullName: updatedUser.fullName || "",
        inGameName: updatedUser.inGameName || "",
        gameId: updatedUser.gameId || "",
        serverId: updatedUser.serverId || "",
        email: updatedUser.email || "",
        whatsapp: updatedUser.whatsapp || "",
        identificacaoGenero: updatedUser.identificacaoGenero || "Prefiro nao informar",
        note: updatedUser.note || "",
        role: updatedUser.role,
        emailVerifiedAt: updatedUser.emailVerifiedAt || null,
        updatedAt: updatedUser.updatedAt || nowIso
      }
    });
  }
);

app.post(
  "/api/org/admin/users/:userNumber/update-role",
  orgWriteLimiter,
  requireCsrf,
  requireOrgSession,
  requireOrgRole(ORG_APPROVAL_ROLES),
  (req, res) => {
    const targetUserNumber = String(req.params.userNumber || "").trim();
    if (!/^[0-9]{4,12}$/.test(targetUserNumber)) {
      apiError(res, 400, "Credencial invalida.");
      return;
    }

    if (safeStringEquals(targetUserNumber, req.orgSession.userNumber)) {
      apiError(res, 400, "Nao e permitido alterar o proprio cargo por este painel.");
      return;
    }

    const parsed = orgUpdateRoleSchema.safeParse(req.body || {});
    if (!parsed.success) {
      apiError(res, 400, "Cargo de destino invalido.");
      return;
    }

    const requestedRole = String(parsed.data.role || "");
    let updatedUser = null;
    const result = updateOrgStore((store) => {
      const targetUser = store.users.find(
        (item) => item.userNumber === targetUserNumber && item.status === "active"
      );
      if (!targetUser) {
        return { error: "Membro nao encontrado.", statusCode: 404 };
      }

      if (!canAssignOrgRole(req.orgSession.role, targetUser.role)) {
        return { error: "Seu cargo nao tem permissao para alterar este membro.", statusCode: 403 };
      }

      if (!canAssignOrgRole(req.orgSession.role, requestedRole)) {
        return { error: "Seu cargo nao tem permissao para atribuir este cargo.", statusCode: 403 };
      }

      if (safeStringEquals(targetUser.role, requestedRole)) {
        return { error: "O membro ja possui este cargo.", statusCode: 409 };
      }

      if (targetUser.role === ORG_OWNER_ROLE && requestedRole !== ORG_OWNER_ROLE) {
        const activeOwners = store.users.filter(
          (item) => item.status === "active" && item.role === ORG_OWNER_ROLE
        ).length;
        if (activeOwners <= 1) {
          return { error: "Nao e permitido remover o ultimo dono ativo.", statusCode: 409 };
        }
      }

      targetUser.role = requestedRole;
      targetUser.updatedAt = new Date().toISOString();
      updatedUser = targetUser;
      return { ok: true };
    });

    if (!result.ok || !updatedUser) {
      apiError(res, result.statusCode || 409, result.error || "Nao foi possivel atualizar o cargo.");
      return;
    }

    for (const session of orgSessions.values()) {
      if (session.userId === updatedUser.id) {
        session.role = updatedUser.role;
      }
    }

    const message =
      `Atualizacao Fatality: seu cargo interno foi atualizado para ${updatedUser.role}. ` +
      "Use seu painel para revisar os novos acessos.";
    enqueueOrgDelivery("email", updatedUser.email, message, {
      type: "role_changed",
      userNumber: updatedUser.userNumber,
      role: updatedUser.role
    });
    if (String(updatedUser.whatsapp || "").trim()) {
      enqueueOrgDelivery("whatsapp", updatedUser.whatsapp, message, {
        type: "role_changed",
        userNumber: updatedUser.userNumber,
        role: updatedUser.role
      });
    }

    audit("org.user_role_updated", req, {
      actor: req.orgSession.userNumber,
      target: updatedUser.userNumber,
      role: updatedUser.role
    });

    res.json({
      ok: true,
      userNumber: updatedUser.userNumber,
      role: updatedUser.role,
      message: "Cargo do membro atualizado com sucesso."
    });
  }
);

app.post(
  "/api/org/admin/users/:userNumber/remove",
  orgWriteLimiter,
  requireCsrf,
  requireOrgSession,
  requireOrgRole(ORG_APPROVAL_ROLES),
  (req, res) => {
    const targetUserNumber = String(req.params.userNumber || "").trim();
    if (!/^[0-9]{4,12}$/.test(targetUserNumber)) {
      apiError(res, 400, "Credencial invalida.");
      return;
    }

    if (safeStringEquals(targetUserNumber, req.orgSession.userNumber)) {
      apiError(res, 400, "Nao e permitido remover a propria conta por este painel.");
      return;
    }

    const parsed = orgRemoveUserSchema.safeParse(req.body || {});
    if (!parsed.success) {
      apiError(res, 400, "Dados invalidos para remocao.");
      return;
    }

    const reason = String(parsed.data.reason || "").trim();
    let removedUser = null;
    const result = updateOrgStore((store) => {
      const targetUser = store.users.find(
        (item) => item.userNumber === targetUserNumber && item.status === "active"
      );
      if (!targetUser) {
        return { error: "Membro nao encontrado.", statusCode: 404 };
      }

      if (!canAssignOrgRole(req.orgSession.role, targetUser.role)) {
        return { error: "Seu cargo nao tem permissao para remover este membro.", statusCode: 403 };
      }

      if (targetUser.role === ORG_OWNER_ROLE) {
        const activeOwners = store.users.filter(
          (item) => item.status === "active" && item.role === ORG_OWNER_ROLE
        ).length;
        if (activeOwners <= 1) {
          return { error: "Nao e permitido remover o ultimo dono ativo.", statusCode: 409 };
        }
      }

      const nowIso = new Date().toISOString();
      targetUser.status = "inactive";
      targetUser.removedAt = nowIso;
      targetUser.removedBy = req.orgSession.userNumber;
      targetUser.removalReason = reason || "Remocao administrativa no painel da org.";
      targetUser.updatedAt = nowIso;
      removedUser = targetUser;
      return { ok: true };
    });

    if (!result.ok || !removedUser) {
      apiError(res, result.statusCode || 409, result.error || "Nao foi possivel remover o membro.");
      return;
    }

    for (const [sessionId, session] of orgSessions.entries()) {
      if (session.userId === removedUser.id) {
        orgSessions.delete(sessionId);
      }
    }

    const removeMessage =
      `Atualizacao Fatality: sua conta interna de credencial ${removedUser.userNumber} ` +
      "foi desativada pela liderança.";
    enqueueOrgDelivery("email", removedUser.email, removeMessage, {
      type: "member_removed",
      userNumber: removedUser.userNumber,
      reason: removedUser.removalReason
    });
    if (String(removedUser.whatsapp || "").trim()) {
      enqueueOrgDelivery("whatsapp", removedUser.whatsapp, removeMessage, {
        type: "member_removed",
        userNumber: removedUser.userNumber,
        reason: removedUser.removalReason
      });
    }

    audit("org.user_removed", req, {
      actor: req.orgSession.userNumber,
      target: removedUser.userNumber,
      role: removedUser.role,
      reason: removedUser.removalReason
    });

    res.json({
      ok: true,
      userNumber: removedUser.userNumber,
      message: "Membro removido com sucesso."
    });
  }
);

app.post(
  "/api/org/admin/users/:userNumber/change-credential",
  orgWriteLimiter,
  requireCsrf,
  requireOrgSession,
  requireOrgRole(ORG_APPROVAL_ROLES),
  (req, res) => {
    const targetUserNumber = String(req.params.userNumber || "").trim();
    if (!/^[0-9]{4,12}$/.test(targetUserNumber)) {
      apiError(res, 400, "Credencial atual invalida.");
      return;
    }

    const parsed = orgChangeCredentialSchema.safeParse(req.body || {});
    if (!parsed.success) {
      apiError(res, 400, "Nova credencial invalida.");
      return;
    }

    const newCredentialNumber = parsed.data.newCredentialNumber;
    if (safeStringEquals(targetUserNumber, newCredentialNumber)) {
      apiError(res, 400, "A nova credencial deve ser diferente da atual.");
      return;
    }

    let updatedUser = null;
    const result = updateOrgStore((store) => {
      const targetUser = store.users.find(
        (item) => item.userNumber === targetUserNumber && item.status === "active"
      );
      if (!targetUser) {
        return { error: "Membro nao encontrado." };
      }

      const numberInUse = store.users.some(
        (item) =>
          item.status === "active" &&
          item.userNumber === newCredentialNumber &&
          item.id !== targetUser.id
      );
      if (numberInUse) {
        return { error: "Esta credencial ja esta em uso." };
      }

      targetUser.userNumber = newCredentialNumber;
      targetUser.updatedAt = new Date().toISOString();
      updatedUser = targetUser;
      return { ok: true };
    });

    if (!result.ok || !updatedUser) {
      apiError(res, 409, result.error || "Nao foi possivel atualizar a credencial.");
      return;
    }

    for (const session of orgSessions.values()) {
      if (session.userId === updatedUser.id) {
        session.userNumber = newCredentialNumber;
      }
    }

    const updateMessage =
      `Atualizacao Fatality: sua credencial foi alterada para ${newCredentialNumber}. ` +
      "Use esse novo numero no proximo login.";
    enqueueOrgDelivery("email", updatedUser.email, updateMessage, {
      type: "credential_number_changed",
      userNumber: newCredentialNumber,
      previousUserNumber: targetUserNumber
    });

    if (String(updatedUser.whatsapp || "").trim()) {
      enqueueOrgDelivery("whatsapp", updatedUser.whatsapp, updateMessage, {
        type: "credential_number_changed",
        userNumber: newCredentialNumber,
        previousUserNumber: targetUserNumber
      });
    }

    audit("org.credential_changed", req, {
      actor: req.orgSession.userNumber,
      targetUserId: updatedUser.id,
      fromUserNumber: targetUserNumber,
      toUserNumber: newCredentialNumber
    });

    res.json({
      ok: true,
      previousCredentialNumber: targetUserNumber,
      credentialNumber: newCredentialNumber,
      message: "Credencial atualizada com sucesso."
    });
  }
);

app.post(
  "/api/org/admin/users/:userNumber/force-reset",
  orgWriteLimiter,
  requireCsrf,
  requireOrgSession,
  requireOrgRole(ORG_APPROVAL_ROLES),
  (req, res) => {
    const parsed = orgForceResetSchema.safeParse(req.body || {});
    if (!parsed.success) {
      apiError(res, 400, "Payload de reset invalido.");
      return;
    }

    const userNumber = String(req.params.userNumber || "").trim();
    const temporaryPassword = parsed.data.newPassword || createTemporaryPassword();
    let targetUser = null;

    const result = updateOrgStore((store) => {
      const user = store.users.find((item) => item.userNumber === userNumber && item.status === "active");
      if (!user) {
        return { error: "Usuario nao encontrado." };
      }

      user.passwordHash = createPasswordHash(temporaryPassword);
      user.mustChangePassword = true;
      user.updatedAt = new Date().toISOString();
      user.temporaryPassword = temporaryPassword;
      user.temporaryPasswordUpdatedAt = user.updatedAt;
      targetUser = user;
      return { ok: true };
    });

    if (!result.ok || !targetUser) {
      apiError(res, 404, result.error || "Nao foi possivel resetar senha.");
      return;
    }

    const resetMessage =
      `Fatality reset administrativo. Credencial: ${targetUser.userNumber}. Nova senha: ${temporaryPassword}.`;

    if (String(targetUser.whatsapp || "").trim()) {
      enqueueOrgDelivery("whatsapp", targetUser.whatsapp, resetMessage, {
        type: "admin_force_reset",
        userNumber: targetUser.userNumber
      });
    }
    enqueueOrgDelivery("email", targetUser.email, resetMessage, {
      type: "admin_force_reset",
      userNumber: targetUser.userNumber
    });

    audit("org.user_force_reset", req, {
      actor: req.orgSession.userNumber,
      target: targetUser.userNumber
    });

    res.json({
      ok: true,
      userNumber: targetUser.userNumber,
      temporaryPassword
    });
  }
);

app.post(
  "/api/org/admin/users/:userNumber/assume",
  orgWriteLimiter,
  requireCsrf,
  requireOrgSession,
  requireOrgRole(ORG_FULL_MANAGEMENT_ROLES),
  (req, res) => {
    const userNumber = String(req.params.userNumber || "").trim();
    const store = readOrgStore();
    const targetUser = store.users.find((item) => item.userNumber === userNumber && item.status === "active");
    if (!targetUser) {
      apiError(res, 404, "Usuario alvo nao encontrado.");
      return;
    }

    const sessionId = createOrgSession(req, targetUser, {
      impersonatedBy: req.orgSession.userNumber
    });
    setOrgSessionCookie(res, sessionId);
    audit("org.owner_assume_user", req, {
      ownerUserNumber: req.orgSession.userNumber,
      targetUserNumber: targetUser.userNumber
    });

    res.json({
      ok: true,
      session: buildOrgSessionResponse(orgSessions.get(sessionId))
    });
  }
);

app.get("/api/org/admin/outbox", requireOrgSession, requireOrgRole(ORG_FULL_MANAGEMENT_ROLES), (req, res) => {
  const limit = normalizeLimit(req.query.limit, 60, 1, 200);
  const items = readLastJsonLines(ORG_DELIVERY_LOG_PATH, limit);
  res.json({ ok: true, total: items.length, items });
});

app.post("/api/recruitment", recruitmentLimiter, requireCsrf, (req, res) => {
  const parsed = recruitmentSchema.safeParse(req.body);
  if (!parsed.success) {
    addRisk(req, 3, "recruitment_invalid_payload");
    audit("recruitment.invalid_payload", req, {
      issues: parsed.error.issues.map((issue) => ({ path: issue.path.join("."), code: issue.code }))
    });
    apiError(res, 400, "Payload invalido.");
    return;
  }

  const { honeypot, envelope, client } = parsed.data;

  if (honeypot.length > 0) {
    addRisk(req, 8, "recruitment_honeypot");
    audit("recruitment.honeypot_triggered", req, {});
    res.status(202).json({ ok: true, submissionId: crypto.randomUUID() });
    return;
  }

  const envelopeValidation = validateEnvelope(envelope);
  if (!envelopeValidation.ok) {
    addRisk(req, 5, "recruitment_invalid_envelope");
    audit("recruitment.invalid_envelope", req, { reason: envelopeValidation.reason });
    apiError(res, 400, "Envelope criptografado invalido.");
    return;
  }

  let parsedRecruitmentPayload = null;
  try {
    const decryptedPayload = decryptRecruitmentEnvelope(envelope);
    const parsedPayloadResult = recruitmentPayloadSchema.safeParse(decryptedPayload);
    if (!parsedPayloadResult.success) {
      addRisk(req, 4, "recruitment_invalid_decrypted_payload");
      audit("recruitment.invalid_decrypted_payload", req, {
        issues: parsedPayloadResult.error.issues.map((issue) => ({
          path: issue.path.join("."),
          code: issue.code
        }))
      });
      apiError(res, 400, "Dados descriptografados invalidos.");
      return;
    }

    parsedRecruitmentPayload = parsedPayloadResult.data;
  } catch (error) {
    addRisk(req, 6, "recruitment_decrypt_failed");
    audit("recruitment.decrypt_failed", req, {
      reason: String(error?.message || "decrypt_failed")
    });
    apiError(res, 400, "Nao foi possivel validar os dados criptografados.");
    return;
  }

  const submissionId = crypto.randomUUID();
  const submissionRecord = {
    id: submissionId,
    receivedAt: new Date().toISOString(),
    requestId: req.requestId,
    ipHash: getRequestIpHash(req),
    userAgentHash: getRequestUserAgentHash(req),
    client,
    encryption: {
      algorithm: "RSA-OAEP-256/AES-GCM-256",
      keyId: PUBLIC_KEY_ID,
      envelope
    }
  };

  appendJsonLine(SUBMISSIONS_PATH, submissionRecord);
  const preRegistration = {
    id: crypto.randomUUID(),
    submissionId,
    source: "recruitment_form",
    status: "pending",
    createdAt: new Date().toISOString(),
    jogo: parsedRecruitmentPayload.jogo,
    nomeCompleto: parsedRecruitmentPayload.nomeCompleto,
    nickInGame: parsedRecruitmentPayload.nickInGame,
    eloMaximo: parsedRecruitmentPayload.eloMaximo,
    wrRanked: parsedRecruitmentPayload.wrRanked,
    maximoEstrelas: parsedRecruitmentPayload.maximoEstrelas,
    rotaPrincipal: parsedRecruitmentPayload.rotaPrincipal,
    horarioDisponivel: parsedRecruitmentPayload.horarioDisponivel,
    identificacaoGenero: parsedRecruitmentPayload.identificacaoGenero,
    discord: parsedRecruitmentPayload.discord,
    idJogo: parsedRecruitmentPayload.idJogo,
    serverJogo: parsedRecruitmentPayload.serverJogo,
    whatsapp: parsedRecruitmentPayload.whatsapp,
    enviadoEm: parsedRecruitmentPayload.enviadoEm || new Date().toISOString()
  };
  updateOrgStore((store) => {
    if (!Array.isArray(store.preRegistrations)) {
      store.preRegistrations = [];
    }
    store.preRegistrations.unshift(preRegistration);
    if (store.preRegistrations.length > 1500) {
      store.preRegistrations = store.preRegistrations.slice(0, 1500);
    }
    return {};
  });
  reduceRisk(req, 1);
  audit("recruitment.accepted", req, { submissionId, keyId: PUBLIC_KEY_ID });
  audit("org.pre_registration_saved", req, {
    preRegistrationId: preRegistration.id,
    submissionId
  });

  res.status(201).json({ ok: true, submissionId });
});

if (!ADMIN_SURFACE_ENABLED) {
  app.use(["/admin", "/admin.html", "/admin.js", "/api/admin"], (req, res) => {
    if ((req.originalUrl || "").startsWith("/api/")) {
      apiError(res, 404, "Rota nao encontrada.");
      return;
    }

    res.status(404).send("Pagina nao encontrada.");
  });
}

app.post("/api/admin/login", loginLimiter, requireCsrf, (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    audit("admin.login_invalid_payload", req, {});
    apiError(res, 400, "Credenciais invalidas.");
    return;
  }

  const username = parsed.data.username.trim();
  const password = parsed.data.password;

  const usernameMatches = safeStringEquals(username.toLowerCase(), ADMIN_USERNAME.toLowerCase());
  const hashForCheck = usernameMatches ? ADMIN_PASSWORD_HASH : DUMMY_PASSWORD_HASH;
  const passwordMatches = verifyPassword(password, hashForCheck);

  if (!(usernameMatches && passwordMatches)) {
    addRisk(req, 7, "admin_login_failed");
    audit("admin.login_failed", req, {});
    apiError(res, 401, "Credenciais invalidas.");
    return;
  }

  const sessionId = createSession(req, ADMIN_USERNAME);
  clearRisk(req);
  setSessionCookie(res, sessionId);

  audit("admin.login_success", req, { username: ADMIN_USERNAME });
  res.json({ ok: true, username: ADMIN_USERNAME });
});

app.post("/api/admin/logout", requireCsrf, requireAdminSession, (req, res) => {
  sessions.delete(req.adminSession.sessionId);
  clearSessionCookie(res);
  audit("admin.logout", req, { username: req.adminSession.username });
  res.json({ ok: true });
});

app.get("/api/admin/session", requireAdminSession, (req, res) => {
  res.json({
    ok: true,
    username: req.adminSession.username,
    expiresAt: req.adminSession.expiresAt
  });
});

app.get("/api/admin/submissions", requireAdminSession, (req, res) => {
  const limit = normalizeLimit(req.query.limit, 100, 1, 300);
  const items = readLastJsonLines(SUBMISSIONS_PATH, limit);

  res.json({
    ok: true,
    total: items.length,
    items
  });
});

app.get("/api/admin/audit", requireAdminSession, (req, res) => {
  const limit = normalizeLimit(req.query.limit, 120, 1, 400);
  const items = readLastJsonLines(AUDIT_PATH, limit);

  res.json({
    ok: true,
    total: items.length,
    items
  });
});

app.use("/assets", express.static(path.join(APP_DIR, "assets"), {
  index: false,
  dotfiles: "deny",
  maxAge: "7d"
}));

app.get(["/", "/index.html"], (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(APP_DIR, "index.html"));
});

app.get(["/formulario", "/formulario.html"], (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(APP_DIR, "formulario.html"));
});

app.get(["/login", "/login.html"], (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(APP_DIR, "login.html"));
});

app.get(["/confirmar-email", "/confirmar-email.html"], (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(APP_DIR, "confirmar-email.html"));
});

app.get(["/termos", "/termos.html"], (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(APP_DIR, "termos.html"));
});

app.get(["/politica", "/politica.html"], (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(APP_DIR, "politica.html"));
});

app.get(["/privacidade", "/privacidade.html"], (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(APP_DIR, "privacidade.html"));
});

app.get("/favicon.ico", (_req, res) => {
  res.setHeader("Cache-Control", "public, max-age=2592000, immutable");
  res.sendFile(path.join(APP_DIR, "favicon.ico"));
});

app.get("/robots.txt", (_req, res) => {
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.sendFile(path.join(APP_DIR, "robots.txt"));
});

app.get("/sitemap.xml", (_req, res) => {
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.sendFile(path.join(APP_DIR, "sitemap.xml"));
});

app.get("/styles.css", (_req, res) => {
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.sendFile(path.join(APP_DIR, "styles.css"));
});

app.get("/script.js", (_req, res) => {
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.sendFile(path.join(APP_DIR, "script.js"));
});

app.get("/anti-inspect.js", (_req, res) => {
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.sendFile(path.join(APP_DIR, "anti-inspect.js"));
});

app.get(["/admin", "/admin.html"], (_req, res) => {
  res.sendFile(path.join(APP_DIR, "admin.html"));
});

app.get("/admin.js", (_req, res) => {
  res.sendFile(path.join(APP_DIR, "admin.js"));
});

app.use(["/certs", "/data", "/logs", "/keys", "/secrets", "/scripts"], (_req, res) => {
  res.status(404).send("Not Found");
});

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    apiError(res, 404, "Rota nao encontrada.");
    return;
  }

  res.status(404).send("Pagina nao encontrada.");
});

app.use((error, req, res, _next) => {
  if (error?.type === "entity.too.large") {
    addRisk(req, 5, "payload_too_large");
    apiError(res, 413, "Payload excede o tamanho permitido.");
    return;
  }

  if (error instanceof SyntaxError && error.status === 400 && "body" in error) {
    addRisk(req, 4, "malformed_json");
    apiError(res, 400, "JSON invalido.");
    return;
  }

  audit("server.exception", req, { message: String(error?.message || "unknown") });

  if (req.path.startsWith("/api/")) {
    apiError(res, 500, "Erro interno.");
    return;
  }

  res.status(500).send("Erro interno.");
});

if (USE_PLATFORM_TLS) {
  listenWithPortFallback(
    "servidor HTTP (TLS na plataforma)",
    () => http.createServer(app),
    HTTP_PORTS,
    (_server, httpPort) => {
      console.log("Servidor Fatality iniciado em modo plataforma.");
      console.log(
        "HTTPS/TLS deve ser finalizado pelo provedor (Cloudflare, Render, Railway, Fly.io, etc.)."
      );
      console.log(`Servidor app em ${formatUrl("http", PUBLIC_PRIMARY_DOMAIN, httpPort)}`);
      console.log("Pressione Ctrl + C para parar.");
    },
    true
  );
} else {
  const httpsOptions = loadHttpsOptions();

  listenWithPortFallback(
    "servidor HTTPS",
    () => https.createServer(httpsOptions, app),
    HTTPS_PORTS,
    (httpsServer, httpsPort) => {
      void httpsServer;
      console.log("Servidor seguro Fatality iniciado.");
      console.log(`Dominio oficial: ${formatUrl("https", PUBLIC_PRIMARY_DOMAIN, httpsPort)}`);
      for (const fallbackDomain of LOCAL_FALLBACK_DOMAINS) {
        if (!fallbackDomain || fallbackDomain === PUBLIC_PRIMARY_DOMAIN) {
          continue;
        }

        console.log(`Acesso local: ${formatUrl("https", fallbackDomain, httpsPort)}`);
      }

      listenWithPortFallback(
        "redirect HTTP -> HTTPS",
        () =>
          http.createServer((req, res) => {
            const hostHeader = String(req.headers.host || PUBLIC_PRIMARY_DOMAIN);
            const hostName = hostHeader.split(":")[0] || PUBLIC_PRIMARY_DOMAIN;
            const redirectTarget = formatUrl("https", hostName, httpsPort) + (req.url || "/");

            res.writeHead(308, {
              Location: redirectTarget,
              "Content-Type": "text/plain; charset=utf-8"
            });
            res.end("Use HTTPS");
          }),
        HTTP_PORTS,
        (_server, httpPort) => {
          console.log(`Redirect HTTP ativo em ${formatUrl("http", PUBLIC_PRIMARY_DOMAIN, httpPort)}`);
          console.log("Pressione Ctrl + C para parar.");
        },
        false
      );
    },
    true
  );
}

function ensureDir(targetDir) {
  fs.mkdirSync(targetDir, { recursive: true });
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

function parsePortList(rawValue, fallback) {
  if (!rawValue) {
    return fallback;
  }

  const ports = String(rawValue)
    .split(",")
    .map((value) => Number.parseInt(value.trim(), 10))
    .filter((value) => Number.isInteger(value) && value > 0 && value < 65536);

  return ports.length > 0 ? ports : fallback;
}

function parseDomainList(rawValue) {
  const values = String(rawValue || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter((value) => value.length > 0);

  return values.length > 0 ? Array.from(new Set(values)) : ["fatality.local", "fatality.lvh.me"];
}

function parseTrustProxy(rawValue) {
  const value = String(rawValue || "").trim().toLowerCase();
  if (!value || value === "0" || value === "false" || value === "off" || value === "no") {
    return false;
  }

  if (value === "true" || value === "on" || value === "yes") {
    return true;
  }

  const hops = Number.parseInt(value, 10);
  if (Number.isInteger(hops) && hops >= 0) {
    return hops;
  }

  return false;
}

function buildCloudflareProxyChecker(filePath) {
  if (!fs.existsSync(filePath)) {
    return () => false;
  }

  const blockList = new net.BlockList();
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);

  for (const line of lines) {
    const value = line.trim();
    if (!value || value.startsWith("#")) {
      continue;
    }

    const slash = value.indexOf("/");
    if (slash <= 0) {
      continue;
    }

    const ip = value.slice(0, slash).trim();
    const prefix = Number.parseInt(value.slice(slash + 1).trim(), 10);
    const ipType = net.isIP(ip);
    if (!ipType || !Number.isInteger(prefix)) {
      continue;
    }

    blockList.addSubnet(ip, prefix, ipType === 6 ? "ipv6" : "ipv4");
  }

  return (candidateIp) => {
    const normalized = normalizeIp(candidateIp);
    const ipType = net.isIP(normalized);
    if (!ipType) {
      return false;
    }

    return blockList.check(normalized, ipType === 6 ? "ipv6" : "ipv4");
  };
}

function createSha256Hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function hmacSign(value) {
  return crypto.createHmac("sha256", APP_HMAC_SECRET).update(value).digest("base64url");
}

function safeStringEquals(left, right) {
  const leftBuffer = Buffer.from(String(left), "utf8");
  const rightBuffer = Buffer.from(String(right), "utf8");

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function getOrCreateSecret(filePath, minLength = 32) {
  if (fs.existsSync(filePath)) {
    const value = fs.readFileSync(filePath, "utf8").trim();
    if (value.length >= minLength) {
      return value;
    }
  }

  const generated = randomToken(64);
  fs.writeFileSync(filePath, generated + "\n", { encoding: "utf8" });
  return generated;
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

function verifyPassword(password, encoded) {
  const parts = String(encoded || "").split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") {
    return false;
  }

  const N = Number.parseInt(parts[1], 10);
  const r = Number.parseInt(parts[2], 10);
  const p = Number.parseInt(parts[3], 10);
  const salt = parts[4];
  const expectedHash = parts[5];

  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) {
    return false;
  }

  const expectedBuffer = Buffer.from(expectedHash, "base64url");
  const actualBuffer = crypto.scryptSync(password, salt, expectedBuffer.length, {
    N,
    r,
    p,
    maxmem: 128 * 1024 * 1024
  });

  if (actualBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

function ensureAdminPasswordHash() {
  if (process.env.ADMIN_PASSWORD_HASH) {
    return process.env.ADMIN_PASSWORD_HASH;
  }

  if (fs.existsSync(ADMIN_HASH_PATH)) {
    const hash = fs.readFileSync(ADMIN_HASH_PATH, "utf8").trim();
    if (hash) {
      return hash;
    }
  }

  const temporaryPassword = randomToken(18);
  const generatedHash = createPasswordHash(temporaryPassword);

  fs.writeFileSync(ADMIN_HASH_PATH, generatedHash + "\n", { encoding: "utf8" });
  fs.writeFileSync(
    ADMIN_TEMP_PASSWORD_PATH,
    [
      "Senha admin temporaria (troque imediatamente):",
      temporaryPassword,
      "",
      "Use: node scripts/set-admin-password.js \"NOVA_SENHA_FORTE\""
    ].join("\n"),
    { encoding: "utf8" }
  );

  console.warn("[security] ADMIN_PASSWORD_HASH nao encontrado.");
  console.warn(`[security] Senha temporaria salva em: ${ADMIN_TEMP_PASSWORD_PATH}`);

  return generatedHash;
}

function ensureE2EKeypair() {
  const hasPublic = fs.existsSync(E2E_PUBLIC_KEY_PATH);
  const hasPrivate = fs.existsSync(E2E_PRIVATE_KEY_PATH);
  const hasPass = fs.existsSync(E2E_PRIVATE_PASS_PATH);

  if (hasPublic && hasPrivate && hasPass) {
    return;
  }

  const privatePassphrase = randomToken(32);
  const pair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: "spki",
      format: "pem"
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: privatePassphrase
    }
  });

  fs.writeFileSync(E2E_PUBLIC_KEY_PATH, pair.publicKey, { encoding: "utf8" });
  fs.writeFileSync(E2E_PRIVATE_KEY_PATH, pair.privateKey, { encoding: "utf8" });
  fs.writeFileSync(E2E_PRIVATE_PASS_PATH, privatePassphrase + "\n", { encoding: "utf8" });

  console.warn("[security] Par de chaves E2E criado automaticamente.");
  console.warn(`[security] Chave publica: ${E2E_PUBLIC_KEY_PATH}`);
  console.warn(`[security] Chave privada criptografada: ${E2E_PRIVATE_KEY_PATH}`);
}

function issueCsrfToken(res) {
  const token = randomToken(32);
  const signature = hmacSign(token);

  const cookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: csrfTtlMs
  };

  res.cookie(CSRF_COOKIE, token, cookieOptions);
  res.cookie(CSRF_SIG_COOKIE, signature, cookieOptions);
  return token;
}

function requireCsrf(req, res, next) {
  const tokenCookie = req.cookies[CSRF_COOKIE] || "";
  const sigCookie = req.cookies[CSRF_SIG_COOKIE] || "";
  const headerToken = String(req.get("X-CSRF-Token") || "");

  if (!tokenCookie || !sigCookie || !headerToken) {
    addRisk(req, 4, "csrf_missing");
    audit("security.csrf_missing", req, {});
    apiError(res, 403, "Falha na validacao CSRF.");
    return;
  }

  const expectedSig = hmacSign(tokenCookie);
  const tokenMatches = safeStringEquals(headerToken, tokenCookie);
  const signatureMatches = safeStringEquals(sigCookie, expectedSig);

  if (!tokenMatches || !signatureMatches) {
    addRisk(req, 4, "csrf_invalid");
    audit("security.csrf_invalid", req, {});
    apiError(res, 403, "Falha na validacao CSRF.");
    return;
  }

  next();
}

function getRequestIp(req) {
  const socketIp = normalizeIp(String(req.socket?.remoteAddress || "unknown"));

  if (useCloudflareConnectingIp) {
    const fromCloudflare = cloudflareProxyChecker(socketIp) || isLocalIp(socketIp);
    const cfIp = normalizeIp(String(req.get("cf-connecting-ip") || ""));
    if (fromCloudflare && cfIp && cfIp !== "unknown") {
      return cfIp;
    }
  }

  return normalizeIp(String(req.ip || socketIp || "unknown"));
}

function getRequestIpHash(req) {
  return createSha256Hex(`${APP_HMAC_SECRET}|ip|${getRequestIp(req)}`);
}

function getRequestUserAgentHash(req) {
  const userAgent = String(req.get("user-agent") || "unknown");
  return createSha256Hex(`${APP_HMAC_SECRET}|ua|${userAgent}`);
}

function createSession(req, username) {
  const sessionId = randomToken(48);
  const now = Date.now();

  sessions.set(sessionId, {
    sessionId,
    username,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + sessionTtlMs).toISOString(),
    ipHash: getRequestIpHash(req),
    userAgentHash: getRequestUserAgentHash(req)
  });

  return sessionId;
}

function setSessionCookie(res, sessionId) {
  res.cookie(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: sessionTtlMs
  });
}

function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/"
  });
}

function cleanExpiredSessions() {
  const now = Date.now();

  for (const [sessionId, session] of sessions.entries()) {
    if (new Date(session.expiresAt).getTime() <= now) {
      sessions.delete(sessionId);
    }
  }
}

function requireAdminSession(req, res, next) {
  const sessionId = String(req.cookies[SESSION_COOKIE] || "");
  if (!sessionId || !sessions.has(sessionId)) {
    addRisk(req, 3, "admin_session_missing");
    apiError(res, 401, "Autenticacao necessaria.");
    return;
  }

  const session = sessions.get(sessionId);
  const now = Date.now();

  if (new Date(session.expiresAt).getTime() <= now) {
    sessions.delete(sessionId);
    clearSessionCookie(res);
    addRisk(req, 2, "admin_session_expired");
    apiError(res, 401, "Sessao expirada.");
    return;
  }

  const sameIp = safeStringEquals(session.ipHash, getRequestIpHash(req));
  const sameUserAgent = safeStringEquals(session.userAgentHash, getRequestUserAgentHash(req));

  if (!sameIp || !sameUserAgent) {
    sessions.delete(sessionId);
    clearSessionCookie(res);
    addRisk(req, 8, "admin_session_binding_failed");
    audit("admin.session_binding_failed", req, {});
    apiError(res, 401, "Sessao invalida.");
    return;
  }

  req.adminSession = session;
  next();
}

function initializeOrgStore() {
  if (!fs.existsSync(ORG_AUTH_STORE_PATH)) {
    const initialStore = {
      version: 1,
      nextUserNumber: 100001,
      users: [],
      requests: [],
      preRegistrations: [],
      performanceUpdates: [],
      resetTokens: [],
      registrationVerifications: [],
      emailVerifications: []
    };
    fs.writeFileSync(ORG_AUTH_STORE_PATH, JSON.stringify(initialStore, null, 2) + "\n", {
      encoding: "utf8"
    });
  }

  const createdOwners = [];

  updateOrgStore((store) => {
    for (let index = 0; index < OWNER_FIXED_NUMBERS.length; index += 1) {
      const fixedUserNumber = OWNER_FIXED_NUMBERS[index];
      const fixedPassword = getConfiguredOwnerPassword(fixedUserNumber);
      let ownerUser = store.users.find((user) => user.userNumber === fixedUserNumber);
      if (ownerUser) {
        ownerUser.role = ORG_OWNER_ROLE;
        ownerUser.status = "active";
        ownerUser.emailVerifiedAt = ownerUser.emailVerifiedAt || new Date().toISOString();
        if (fixedPassword) {
          ownerUser.passwordHash = createPasswordHash(fixedPassword);
          ownerUser.mustChangePassword = false;
          ownerUser.temporaryPassword = fixedPassword;
          ownerUser.temporaryPasswordUpdatedAt = new Date().toISOString();
        }
        ownerUser.updatedAt = new Date().toISOString();
        continue;
      }

      const tempPassword = fixedPassword || createTemporaryPassword();
      ownerUser = {
        id: crypto.randomUUID(),
        userNumber: fixedUserNumber,
        fullName: `Owner Fatality ${index + 1}`,
        username: `owner${index + 1}`,
        email: `owner${index + 1}@fatality-e-sports-official.com.br`,
        whatsapp: "00000000000",
        role: ORG_OWNER_ROLE,
        status: "active",
        mustChangePassword: !fixedPassword,
        emailVerifiedAt: new Date().toISOString(),
        approvedAt: new Date().toISOString(),
        approvedBy: "system",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        passwordHash: createPasswordHash(tempPassword),
        temporaryPassword: tempPassword,
        temporaryPasswordUpdatedAt: new Date().toISOString()
      };

      store.users.push(ownerUser);
      createdOwners.push({
        userNumber: fixedUserNumber,
        tempPassword
      });
    }

    return {};
  });

  if (createdOwners.length > 0) {
    const lines = [
      `Gerado em: ${new Date().toISOString()}`,
      "Credenciais iniciais dos donos (troque no primeiro acesso):",
      ...createdOwners.map((item) => `Usuario ${item.userNumber} | Senha ${item.tempPassword}`),
      ""
    ];
    fs.appendFileSync(ORG_OWNER_BOOTSTRAP_PATH, lines.join("\n"), { encoding: "utf8" });
    console.warn("[security] Donos iniciais da org criados.");
    console.warn(`[security] Credenciais bootstrap em: ${ORG_OWNER_BOOTSTRAP_PATH}`);
  }
}

function parseFixedUserNumbers(rawValue) {
  const values = String(rawValue || "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => /^[0-9]{4,12}$/.test(entry));

  return values.length > 0 ? Array.from(new Set(values)) : ["900001"];
}

function getConfiguredOwnerPassword(userNumber) {
  const envKey = `ORG_OWNER_PASSWORD_${userNumber}`;
  const value = String(process.env[envKey] || "").trim();
  if (!value) {
    return "";
  }

  if (value.length < 8 || value.length > 160) {
    console.warn(
      `[security] ${envKey} ignorada: senha deve ter entre 8 e 160 caracteres.`
    );
    return "";
  }

  return value;
}

function readOrgStore() {
  if (!fs.existsSync(ORG_AUTH_STORE_PATH)) {
    return {
      version: 1,
      nextUserNumber: 100001,
      users: [],
      requests: [],
      preRegistrations: [],
      performanceUpdates: [],
      resetTokens: [],
      registrationVerifications: [],
      emailVerifications: []
    };
  }

  try {
    const raw = fs.readFileSync(ORG_AUTH_STORE_PATH, "utf8");
    const normalizedRaw = raw.replace(/^\uFEFF/, "");
    const parsed = JSON.parse(normalizedRaw);
    if (!parsed || typeof parsed !== "object") {
      throw new Error("invalid_store");
    }

    return {
      version: 1,
      nextUserNumber: Number.isInteger(parsed.nextUserNumber) ? parsed.nextUserNumber : 100001,
      users: Array.isArray(parsed.users) ? parsed.users : [],
      requests: Array.isArray(parsed.requests) ? parsed.requests : [],
      preRegistrations: Array.isArray(parsed.preRegistrations) ? parsed.preRegistrations : [],
      performanceUpdates: Array.isArray(parsed.performanceUpdates) ? parsed.performanceUpdates : [],
      resetTokens: Array.isArray(parsed.resetTokens) ? parsed.resetTokens : [],
      registrationVerifications: Array.isArray(parsed.registrationVerifications)
        ? parsed.registrationVerifications
        : [],
      emailVerifications: Array.isArray(parsed.emailVerifications) ? parsed.emailVerifications : []
    };
  } catch {
    return {
      version: 1,
      nextUserNumber: 100001,
      users: [],
      requests: [],
      preRegistrations: [],
      performanceUpdates: [],
      resetTokens: [],
      registrationVerifications: [],
      emailVerifications: []
    };
  }
}

function updateOrgStore(mutator) {
  const store = readOrgStore();
  const result = mutator(store) || {};
  fs.writeFileSync(ORG_AUTH_STORE_PATH, JSON.stringify(store, null, 2) + "\n", { encoding: "utf8" });
  return {
    ok: !result.error,
    ...result
  };
}

function allocateOrgUserNumber(store) {
  const used = new Set(store.users.map((user) => user.userNumber));

  let current = Number.isInteger(store.nextUserNumber) ? store.nextUserNumber : 100001;
  if (current < 100001) {
    current = 100001;
  }

  while (used.has(String(current))) {
    current += 1;
  }

  const allocated = String(current);
  store.nextUserNumber = current + 1;
  return allocated;
}

function createTemporaryPassword() {
  let base = "";
  while (base.length < 14) {
    base += randomToken(12).replace(/[^A-Za-z0-9]/g, "");
  }

  return base.slice(0, 14) + "A1!";
}

function createNumericToken(length) {
  const bytes = crypto.randomBytes(length);
  let token = "";
  for (let i = 0; i < length; i += 1) {
    token += String(bytes[i] % 10);
  }

  return token;
}

function getIsoWeekKey(date = new Date()) {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const weekNo = Math.ceil(((d - yearStart) / 86400000 + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(weekNo).padStart(2, "0")}`;
}

function clampNumber(value, min, max) {
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return min;
  }
  return Math.min(max, Math.max(min, num));
}

function averageNumbers(values) {
  if (!Array.isArray(values) || values.length === 0) {
    return 0;
  }

  let sum = 0;
  let count = 0;

  for (const raw of values) {
    const num = Number(raw);
    if (!Number.isFinite(num)) {
      continue;
    }

    sum += num;
    count += 1;
  }

  return count === 0 ? 0 : sum / count;
}

function computePercentFromScores(scores) {
  const keys = ORG_PERFORMANCE_CATEGORY_KEYS;
  const values = keys.map((key) => clampNumber(scores?.[key], 0, 10));
  const avg = averageNumbers(values);
  return Math.round((avg / 10) * 1000) / 10;
}

function normalizePerformanceBullets(items) {
  if (!Array.isArray(items)) {
    return [];
  }

  const seen = new Set();
  const out = [];
  for (const raw of items) {
    const value = String(raw || "").trim();
    if (!value) {
      continue;
    }
    const key = value.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(value.slice(0, 120));
    if (out.length >= 12) {
      break;
    }
  }
  return out;
}

function computePerformanceSummary(store, playerUserNumber, focusWeekKey = "") {
  const now = new Date();
  const currentWeek = getIsoWeekKey(now);
  const focusWeek = /^[0-9]{4}-W[0-9]{2}$/.test(String(focusWeekKey || "").trim())
    ? String(focusWeekKey || "").trim()
    : currentWeek;

  const updates = (Array.isArray(store.performanceUpdates) ? store.performanceUpdates : [])
    .filter((item) => item && item.playerUserNumber === playerUserNumber)
    .sort((a, b) => String(a.updatedAt || "").localeCompare(String(b.updatedAt || "")));

  const latestUpdatedAt = updates.length > 0 ? updates[updates.length - 1].updatedAt || null : null;

  const byWeek = new Map();
  for (const update of updates) {
    const week = String(update.week || "").trim();
    if (!week) {
      continue;
    }
    if (!byWeek.has(week)) {
      byWeek.set(week, []);
    }
    byWeek.get(week).push(update);
  }

  const weeksSorted = Array.from(byWeek.keys()).sort((a, b) => b.localeCompare(a));
  const recentWeeks = weeksSorted.slice(0, 8).sort((a, b) => a.localeCompare(b));
  const trend = recentWeeks.map((week) => {
    const list = byWeek.get(week) || [];
    const percents = list.map((item) => computePercentFromScores(item.scores));
    return {
      week,
      percent: Math.round(averageNumbers(percents) * 10) / 10
    };
  });

  const focusWeekUpdates = updates.filter((item) => item.week === focusWeek);
  const focusWeekContributors = focusWeekUpdates
    .map((item) => ({
      evaluatorUserNumber: item.evaluatorUserNumber || "",
      evaluatorRole: item.evaluatorRole || "",
      percent: computePercentFromScores(item.scores),
      updatedAt: item.updatedAt || null
    }))
    .sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || "")));

  const allTimeCategory = {};
  const focusWeekCategory = {};

  for (const key of ORG_PERFORMANCE_CATEGORY_KEYS) {
    const allValues = updates.map((item) => clampNumber(item?.scores?.[key], 0, 10));
    const weekValues = focusWeekUpdates.map((item) => clampNumber(item?.scores?.[key], 0, 10));
    allTimeCategory[key] = Math.round(averageNumbers(allValues) * 10) / 10;
    focusWeekCategory[key] = weekValues.length > 0 ? Math.round(averageNumbers(weekValues) * 10) / 10 : null;
  }

  const overallPercent = Math.round((averageNumbers(Object.values(allTimeCategory)) / 10) * 1000) / 10;
  const focusWeekPercent = focusWeekUpdates.length
    ? Math.round((averageNumbers(Object.values(focusWeekCategory).filter((v) => v !== null)) / 10) * 1000) / 10
    : null;

  const strengths = normalizePerformanceBullets(focusWeekUpdates.flatMap((item) => item.strengths || []));
  const improvements = normalizePerformanceBullets(
    focusWeekUpdates.flatMap((item) => item.improvements || [])
  );

  return {
    playerUserNumber,
    week: focusWeek,
    currentWeek,
    lastUpdatedAt: latestUpdatedAt,
    overallPercent,
    currentWeekPercent: focusWeekPercent,
    categories: {
      allTime: allTimeCategory,
      currentWeek: focusWeekCategory
    },
    trend,
    contributors: focusWeekContributors,
    strengths,
    improvements
  };
}

function toInternalUsername(value) {
  const base = String(value || "")
    .normalize("NFKD")
    .replace(/[^\w.\- ]+/g, "")
    .replace(/\s+/g, "_")
    .replace(/_+/g, "_")
    .toLowerCase()
    .trim();

  const candidate = base.replace(/^[_\-.]+|[_\-.]+$/g, "");
  return (candidate || "player").slice(0, 26);
}

function allocateOrgUsername(store, preferredBase) {
  const used = new Set(
    store.users
      .filter((item) => item.status === "active")
      .map((item) => String(item.username || "").toLowerCase())
  );

  const sanitizedBase = toInternalUsername(preferredBase);
  let candidate = sanitizedBase;
  let suffix = 1;

  while (used.has(candidate.toLowerCase())) {
    const tail = String(suffix);
    const maxBase = Math.max(3, 32 - tail.length);
    candidate = `${sanitizedBase.slice(0, maxBase)}${tail}`;
    suffix += 1;
  }

  return candidate;
}

function enqueueOrgDelivery(channel, destination, message, meta = {}) {
  const payload = {
    timestamp: new Date().toISOString(),
    channel,
    destination,
    message,
    meta
  };

  appendJsonLine(ORG_DELIVERY_LOG_PATH, payload);
  void dispatchOrgDelivery(payload);
}

function isPlaceholderValue(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value) {
    return true;
  }

  const lowered = value.toLowerCase();
  return (
    lowered.includes("xxxxxxxx") ||
    lowered.includes("changeme") ||
    lowered.includes("example.com") ||
    lowered.includes("your_") ||
    lowered.includes("your-") ||
    lowered.includes("seu_") ||
    lowered.includes("seu-") ||
    lowered.includes("seuendpoint") ||
    lowered === "replace_me"
  );
}

function isValidHttpUrl(rawValue) {
  try {
    const parsed = new URL(String(rawValue || ""));
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

function hasValidResendConfig() {
  if (!ORG_RESEND_API_KEY || isPlaceholderValue(ORG_RESEND_API_KEY)) {
    return false;
  }

  return ORG_RESEND_API_KEY.startsWith("re_");
}

function hasConfiguredEmailWebhook() {
  return (
    Boolean(ORG_EMAIL_WEBHOOK_URL) &&
    !isPlaceholderValue(ORG_EMAIL_WEBHOOK_URL) &&
    isValidHttpUrl(ORG_EMAIL_WEBHOOK_URL)
  );
}

function hasConfiguredWhatsAppWebhook() {
  return (
    Boolean(ORG_WHATSAPP_WEBHOOK_URL) &&
    !isPlaceholderValue(ORG_WHATSAPP_WEBHOOK_URL) &&
    isValidHttpUrl(ORG_WHATSAPP_WEBHOOK_URL)
  );
}

function hasEmailDeliveryConfigured() {
  if (ORG_EMAIL_PROVIDER === "resend") {
    return hasValidResendConfig() || hasConfiguredEmailWebhook();
  }

  return hasConfiguredEmailWebhook();
}

function hasValidMetaWhatsAppConfig() {
  if (!ORG_META_WA_PHONE_NUMBER_ID || isPlaceholderValue(ORG_META_WA_PHONE_NUMBER_ID)) {
    return false;
  }

  if (!ORG_META_WA_ACCESS_TOKEN || isPlaceholderValue(ORG_META_WA_ACCESS_TOKEN)) {
    return false;
  }

  const normalizedVersion = normalizeMetaGraphVersion(ORG_META_WA_API_VERSION);
  if (!/^v\d+\.\d+$/i.test(normalizedVersion)) {
    return false;
  }

  try {
    const base = new URL(ORG_META_WA_GRAPH_BASE_URL);
    if (base.protocol !== "https:" && base.protocol !== "http:") {
      return false;
    }
  } catch {
    return false;
  }

  return true;
}

function logOrgDeliveryConfigStatus() {
  if (ORG_WHATSAPP_PROVIDER === "meta_cloud") {
    if (!hasValidMetaWhatsAppConfig()) {
      console.warn("[org-delivery] WhatsApp provider=meta_cloud, mas configuracao esta incompleta.");
      console.warn(
        "[org-delivery] Defina ORG_META_WA_PHONE_NUMBER_ID, ORG_META_WA_ACCESS_TOKEN e ORG_META_WA_API_VERSION."
      );
    }
  } else {
    if (!hasConfiguredWhatsAppWebhook()) {
      console.warn("[org-delivery] WhatsApp webhook nao configurado.");
      console.warn("[org-delivery] Defina ORG_WHATSAPP_WEBHOOK_URL para enviar mensagens via WhatsApp.");
    }
  }

  if (ORG_EMAIL_PROVIDER === "resend" && !hasValidResendConfig()) {
    console.warn("[org-delivery] Email provider=resend, mas ORG_RESEND_API_KEY nao esta valido.");
  }

  if (!hasEmailDeliveryConfigured()) {
    console.warn("[org-delivery] Canal de e-mail nao configurado para validacao de cadastro.");
    console.warn("[org-delivery] Configure ORG_EMAIL_PROVIDER + ORG_RESEND_API_KEY ou ORG_EMAIL_WEBHOOK_URL.");
  }
}

async function dispatchOrgDelivery(payload) {
  if (typeof fetch !== "function") {
    return;
  }

  const channel = String(payload.channel || "");
  let delivered = false;

  if (channel === "whatsapp") {
    if (ORG_WHATSAPP_PROVIDER === "meta_cloud") {
      delivered = await sendWhatsAppViaMetaCloud(payload);

      if (!delivered && hasConfiguredWhatsAppWebhook()) {
        delivered = await sendOrgDeliveryWebhook(payload, ORG_WHATSAPP_WEBHOOK_URL, "whatsapp_webhook_fallback");
      }
    } else if (hasConfiguredWhatsAppWebhook()) {
      delivered = await sendOrgDeliveryWebhook(payload, ORG_WHATSAPP_WEBHOOK_URL, "whatsapp_webhook");
    }
  } else if (channel === "email") {
    if (ORG_EMAIL_PROVIDER === "resend") {
      delivered = await sendEmailViaResend(payload);
    }

    if (!delivered && hasConfiguredEmailWebhook()) {
      delivered = await sendOrgDeliveryWebhook(payload, ORG_EMAIL_WEBHOOK_URL, "email_webhook");
    }
  }

  if (delivered) {
    return;
  }

  appendJsonLine(ORG_DELIVERY_LOG_PATH, {
    timestamp: new Date().toISOString(),
    channel: payload.channel,
    destination: payload.destination,
    event: "delivery_not_sent",
    provider: channel === "whatsapp" ? ORG_WHATSAPP_PROVIDER : ORG_EMAIL_PROVIDER
  });
}

async function sendOrgDeliveryWebhook(payload, url, routeLabel) {
  try {
    const response = await fetch(String(url), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Fatality-OrgDelivery/1.0"
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      appendJsonLine(ORG_DELIVERY_LOG_PATH, {
        timestamp: new Date().toISOString(),
        channel: payload.channel,
        destination: payload.destination,
        event: `${routeLabel}_delivery_failed`,
        statusCode: response.status
      });
      return false;
    }

    appendJsonLine(ORG_DELIVERY_LOG_PATH, {
      timestamp: new Date().toISOString(),
      channel: payload.channel,
      destination: payload.destination,
      event: `${routeLabel}_delivery_ok`
    });
    return true;
  } catch (error) {
    appendJsonLine(ORG_DELIVERY_LOG_PATH, {
      timestamp: new Date().toISOString(),
      channel: payload.channel,
      destination: payload.destination,
      event: `${routeLabel}_delivery_exception`,
      message: String(error?.message || "unknown")
    });
    return false;
  }
}

async function sendWhatsAppViaMetaCloud(payload) {
  if (!hasValidMetaWhatsAppConfig()) {
    appendJsonLine(ORG_DELIVERY_LOG_PATH, {
      timestamp: new Date().toISOString(),
      channel: payload.channel,
      destination: payload.destination,
      event: "meta_whatsapp_configuration_missing"
    });
    return false;
  }

  const destination = normalizeWhatsAppDestinationForMeta(payload.destination);
  if (!destination) {
    appendJsonLine(ORG_DELIVERY_LOG_PATH, {
      timestamp: new Date().toISOString(),
      channel: payload.channel,
      destination: payload.destination,
      event: "meta_whatsapp_invalid_destination"
    });
    return false;
  }

  const messageText = String(payload.message || "").trim();
  if (!messageText) {
    appendJsonLine(ORG_DELIVERY_LOG_PATH, {
      timestamp: new Date().toISOString(),
      channel: payload.channel,
      destination: payload.destination,
      event: "meta_whatsapp_empty_message"
    });
    return false;
  }

  const graphBase = ORG_META_WA_GRAPH_BASE_URL.replace(/\/+$/, "");
  const apiVersion = normalizeMetaGraphVersion(ORG_META_WA_API_VERSION);
  const endpoint = `${graphBase}/${apiVersion}/${encodeURIComponent(
    ORG_META_WA_PHONE_NUMBER_ID
  )}/messages`;

  const requestBody = {
    messaging_product: "whatsapp",
    recipient_type: "individual",
    to: destination,
    type: "text",
    text: {
      preview_url: false,
      body: messageText.slice(0, 4096)
    }
  };

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ORG_META_WA_ACCESS_TOKEN}`,
        "Content-Type": "application/json",
        "User-Agent": "Fatality-MetaWhatsApp/1.0"
      },
      body: JSON.stringify(requestBody)
    });

    const responseBody = await response.json().catch(() => ({}));
    if (!response.ok) {
      appendJsonLine(ORG_DELIVERY_LOG_PATH, {
        timestamp: new Date().toISOString(),
        channel: payload.channel,
        destination: payload.destination,
        event: "meta_whatsapp_delivery_failed",
        statusCode: response.status,
        message: responseBody?.error?.message || responseBody?.message || null
      });
      return false;
    }

    appendJsonLine(ORG_DELIVERY_LOG_PATH, {
      timestamp: new Date().toISOString(),
      channel: payload.channel,
      destination: payload.destination,
      event: "meta_whatsapp_delivery_ok",
      id: responseBody?.messages?.[0]?.id || null
    });
    return true;
  } catch (error) {
    appendJsonLine(ORG_DELIVERY_LOG_PATH, {
      timestamp: new Date().toISOString(),
      channel: payload.channel,
      destination: payload.destination,
      event: "meta_whatsapp_delivery_exception",
      message: String(error?.message || "unknown")
    });
    return false;
  }
}

async function sendEmailViaResend(payload) {
  if (!hasValidResendConfig()) {
    appendJsonLine(ORG_DELIVERY_LOG_PATH, {
      timestamp: new Date().toISOString(),
      channel: payload.channel,
      destination: payload.destination,
      event: "resend_configuration_missing"
    });
    return false;
  }

  const destination = String(payload.destination || "").trim();
  if (!destination || !destination.includes("@")) {
    appendJsonLine(ORG_DELIVERY_LOG_PATH, {
      timestamp: new Date().toISOString(),
      channel: payload.channel,
      destination: payload.destination,
      event: "resend_invalid_destination"
    });
    return false;
  }

  const subjectBase = resolveOrgDeliverySubject(payload);
  const subject = ORG_EMAIL_SUBJECT_PREFIX
    ? `${ORG_EMAIL_SUBJECT_PREFIX} ${subjectBase}`.trim()
    : subjectBase;

  const body = {
    from: ORG_EMAIL_FROM,
    to: [destination],
    subject,
    text: String(payload.message || "")
  };

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ORG_RESEND_API_KEY}`,
        "Content-Type": "application/json",
        "User-Agent": "Fatality-OrgDelivery/1.0"
      },
      body: JSON.stringify(body)
    });

    const responseBody = await response.json().catch(() => ({}));
    if (!response.ok) {
      appendJsonLine(ORG_DELIVERY_LOG_PATH, {
        timestamp: new Date().toISOString(),
        channel: payload.channel,
        destination: payload.destination,
        event: "resend_delivery_failed",
        statusCode: response.status,
        message: responseBody?.message || null
      });
      return false;
    }

    appendJsonLine(ORG_DELIVERY_LOG_PATH, {
      timestamp: new Date().toISOString(),
      channel: payload.channel,
      destination: payload.destination,
      event: "resend_delivery_ok",
      id: responseBody?.id || null
    });
    return true;
  } catch (error) {
    appendJsonLine(ORG_DELIVERY_LOG_PATH, {
      timestamp: new Date().toISOString(),
      channel: payload.channel,
      destination: payload.destination,
      event: "resend_delivery_exception",
      message: String(error?.message || "unknown")
    });
    return false;
  }
}

function normalizePhoneDigits(value) {
  return String(value || "").replace(/\D+/g, "");
}

function normalizeWhatsAppDestination(rawValue) {
  const raw = String(rawValue || "").trim();
  if (!raw) {
    return "";
  }

  if (raw.toLowerCase().startsWith("whatsapp:")) {
    return raw;
  }

  const digits = normalizePhoneDigits(raw);
  if (!digits) {
    return "";
  }

  const withCountryCode = digits.length === 10 || digits.length === 11 ? `55${digits}` : digits;
  return `whatsapp:+${withCountryCode}`;
}

function normalizeWhatsAppDestinationForMeta(rawValue) {
  const raw = String(rawValue || "").trim();
  if (!raw) {
    return "";
  }

  const withoutPrefix = raw.toLowerCase().startsWith("whatsapp:") ? raw.slice(9) : raw;
  const digits = normalizePhoneDigits(withoutPrefix);
  if (!digits) {
    return "";
  }

  return digits.length === 10 || digits.length === 11 ? `55${digits}` : digits;
}

function normalizeMetaGraphVersion(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value) {
    return "v21.0";
  }

  return value.toLowerCase().startsWith("v") ? value : `v${value}`;
}

function normalizeOrgWhatsAppProvider(rawValue) {
  const value = String(rawValue || "").trim().toLowerCase();
  if (value === "meta" || value === "meta_cloud" || value === "meta-whatsapp-cloud") {
    return "meta_cloud";
  }

  return "webhook";
}

function resolveOrgDeliverySubject(payload) {
  const metaType = String(payload?.meta?.type || "");
  switch (metaType) {
    case "password_reset":
      return "Confirmacao de recuperacao";
    case "password_reset_email_confirmed":
      return "Senha alterada com confirmacao de e-mail";
    case "register_email_verification":
      return "Codigo de confirmacao de cadastro";
    case "login_email_verification":
      return "Codigo para concluir login";
    case "email_change_verification":
      return "Codigo para troca de e-mail";
    case "email_changed_notice":
      return "Aviso de alteracao de e-mail";
    case "email_verification_reminder":
      return "Lembrete de verificacao de e-mail";
    case "credential_number_changed":
      return "Atualizacao de credencial";
    case "new_credentials":
      return "Acesso aprovado";
    case "admin_force_reset":
      return "Reset administrativo";
    case "role_changed":
      return "Mudanca de cargo";
    case "member_removed":
      return "Remocao de membro";
    default:
      return "Comunicado da organizacao";
  }
}

function createOrgSession(req, user, options = {}) {
  const sessionId = randomToken(48);
  const now = Date.now();
  const session = {
    sessionId,
    userId: user.id,
    userNumber: user.userNumber,
    username: user.username,
    role: user.role,
    fullName: user.fullName,
    email: user.email || "",
    emailVerifiedAt: user.emailVerifiedAt || null,
    mustChangePassword: !!user.mustChangePassword,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + orgSessionTtlMs).toISOString(),
    ipHash: getRequestIpHash(req),
    userAgentHash: getRequestUserAgentHash(req),
    impersonatedBy: options.impersonatedBy || null
  };

  orgSessions.set(sessionId, session);
  return sessionId;
}

function buildOrgSessionResponse(session) {
  if (!session) {
    return null;
  }

  return {
    userNumber: session.userNumber,
    credentialNumber: session.userNumber,
    username: session.username,
    fullName: session.fullName,
    email: session.email || "",
    emailVerifiedAt: session.emailVerifiedAt || null,
    role: session.role,
    mustChangePassword: !!session.mustChangePassword,
    impersonatedBy: session.impersonatedBy || null,
    expiresAt: session.expiresAt
  };
}

function setOrgSessionCookie(res, sessionId) {
  res.cookie(ORG_SESSION_COOKIE, sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: orgSessionTtlMs
  });
}

function clearOrgSessionCookie(res) {
  res.clearCookie(ORG_SESSION_COOKIE, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/"
  });
}

function cleanExpiredOrgSessions() {
  const now = Date.now();
  for (const [sessionId, session] of orgSessions.entries()) {
    if (new Date(session.expiresAt).getTime() <= now) {
      orgSessions.delete(sessionId);
    }
  }
}

function requireOrgSession(req, res, next) {
  const sessionId = String(req.cookies[ORG_SESSION_COOKIE] || "");
  if (!sessionId || !orgSessions.has(sessionId)) {
    addRisk(req, 2, "org_session_missing");
    apiError(res, 401, "Sessao da org nao encontrada.");
    return;
  }

  const session = orgSessions.get(sessionId);
  const now = Date.now();

  if (new Date(session.expiresAt).getTime() <= now) {
    orgSessions.delete(sessionId);
    clearOrgSessionCookie(res);
    addRisk(req, 2, "org_session_expired");
    apiError(res, 401, "Sessao da org expirada.");
    return;
  }

  if (enforceOrgSessionBinding) {
    const sameIp = safeStringEquals(session.ipHash, getRequestIpHash(req));
    const sameUserAgent = safeStringEquals(session.userAgentHash, getRequestUserAgentHash(req));
    if (!sameIp || !sameUserAgent) {
      orgSessions.delete(sessionId);
      clearOrgSessionCookie(res);
      addRisk(req, 6, "org_session_binding_failed");
      audit("org.session_binding_failed", req, {
        userNumber: session.userNumber
      });
      apiError(res, 401, "Sessao invalida.");
      return;
    }
  }

  req.orgSession = session;
  next();
}

function requireOrgRole(allowedRoles) {
  const allowed = new Set(allowedRoles);
  return (req, res, next) => {
    const role = String(req.orgSession?.role || "");
    if (!allowed.has(role)) {
      apiError(res, 403, "Permissao insuficiente para esta operacao.");
      return;
    }

    next();
  };
}

function getAssignableOrgRoles(actorRole) {
  switch (String(actorRole || "")) {
    case "dono":
    case "lider":
      return ["player", "staff", "adm", "vice_lider", "lider", "dono"];
    case "vice_lider":
      return ["player", "staff", "adm", "vice_lider"];
    case "adm":
      return ["player", "staff", "adm"];
    default:
      return [];
  }
}

function canAssignOrgRole(actorRole, targetRole) {
  const allowedTargets = new Set(getAssignableOrgRoles(actorRole));
  return allowedTargets.has(String(targetRole || ""));
}

function validateEnvelope(envelope) {
  const wrappedKey = safeDecodeBase64(envelope.wrappedKey);
  const iv = safeDecodeBase64(envelope.iv);
  const ciphertext = safeDecodeBase64(envelope.ciphertext);

  if (!wrappedKey || wrappedKey.length < 256 || wrappedKey.length > 1024) {
    return { ok: false, reason: "wrappedKey_size" };
  }

  if (!iv || iv.length !== 12) {
    return { ok: false, reason: "iv_size" };
  }

  if (!ciphertext || ciphertext.length < 24 || ciphertext.length > 24000) {
    return { ok: false, reason: "ciphertext_size" };
  }

  return { ok: true };
}

function decryptRecruitmentEnvelope(envelope) {
  const wrappedKey = safeDecodeBase64(envelope?.wrappedKey);
  const iv = safeDecodeBase64(envelope?.iv);
  const combinedCiphertext = safeDecodeBase64(envelope?.ciphertext);

  if (!wrappedKey || !iv || !combinedCiphertext || iv.length !== 12 || combinedCiphertext.length < 17) {
    throw new Error("invalid_envelope");
  }

  const aesKey = crypto.privateDecrypt(
    {
      key: E2E_PRIVATE_KEY_PEM,
      passphrase: E2E_PRIVATE_KEY_PASSPHRASE,
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
  return JSON.parse(plaintextBuffer.toString("utf8"));
}

function safeDecodeBase64(value) {
  try {
    const normalized = String(value || "").trim();
    if (!normalized) {
      return null;
    }

    return Buffer.from(normalized, "base64");
  } catch {
    return null;
  }
}

function appendJsonLine(filePath, value) {
  fs.appendFileSync(filePath, JSON.stringify(value) + "\n", { encoding: "utf8" });
}

function readLastJsonLines(filePath, limit) {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const raw = fs.readFileSync(filePath, "utf8");
  if (!raw.trim()) {
    return [];
  }

  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const picked = lines.slice(-limit).reverse();
  const result = [];

  for (const line of picked) {
    try {
      result.push(JSON.parse(line));
    } catch {
      // Ignore corrupted line and continue.
    }
  }

  return result;
}

function audit(event, req, details) {
  const payload = {
    timestamp: new Date().toISOString(),
    event,
    requestId: req?.requestId || null,
    ipHash: req ? getRequestIpHash(req) : null,
    userAgentHash: req ? getRequestUserAgentHash(req) : null,
    details: details || {}
  };

  appendJsonLine(AUDIT_PATH, payload);
}

function normalizeLimit(rawValue, defaultValue, min, max) {
  const parsed = Number.parseInt(String(rawValue || ""), 10);
  if (!Number.isInteger(parsed)) {
    return defaultValue;
  }

  return Math.min(max, Math.max(min, parsed));
}

function apiError(res, statusCode, message) {
  res.status(statusCode).json({ ok: false, error: message });
}

function loadHttpsOptions() {
  if (!fs.existsSync(HTTPS_PFX_PATH)) {
    console.error("Certificado HTTPS nao encontrado.");
    console.error(`Esperado em: ${HTTPS_PFX_PATH}`);
    console.error("Execute: .\\setup-local-https.ps1");
    process.exit(1);
  }

  let passphrase = process.env.HTTPS_PFX_PASSWORD || "";
  if (!passphrase && fs.existsSync(HTTPS_PFX_PASSWORD_FILE)) {
    passphrase = fs.readFileSync(HTTPS_PFX_PASSWORD_FILE, "utf8").trim();
  }

  if (!passphrase) {
    console.error("Senha do certificado HTTPS nao encontrada.");
    console.error(`Defina HTTPS_PFX_PASSWORD ou use ${HTTPS_PFX_PASSWORD_FILE}.`);
    process.exit(1);
  }

  return {
    pfx: fs.readFileSync(HTTPS_PFX_PATH),
    passphrase
  };
}

function listenWithPortFallback(label, factory, ports, onReady, exitOnFailure, index = 0) {
  const port = ports[index];
  const server = factory();
  hardenNodeServer(server);

  server.once("error", (error) => {
    if (error.code === "EADDRINUSE" && index < ports.length - 1) {
      console.warn(`Porta ${port} em uso para ${label}. Tentando proxima porta...`);
      listenWithPortFallback(label, factory, ports, onReady, exitOnFailure, index + 1);
      return;
    }

    console.error(`Falha ao iniciar ${label}: ${error.message}`);
    if (exitOnFailure) {
      process.exit(1);
    }
  });

  server.listen(port, HOST, () => {
    onReady(server, port);
  });
}

function hardenNodeServer(server) {
  server.requestTimeout = Number.parseInt(process.env.SERVER_REQUEST_TIMEOUT_MS || "10000", 10);
  server.headersTimeout = Number.parseInt(process.env.SERVER_HEADERS_TIMEOUT_MS || "8000", 10);
  server.keepAliveTimeout = Number.parseInt(process.env.SERVER_KEEP_ALIVE_TIMEOUT_MS || "4000", 10);
  server.maxRequestsPerSocket = Number.parseInt(
    process.env.SERVER_MAX_REQUESTS_PER_SOCKET || "80",
    10
  );
  server.timeout = Number.parseInt(process.env.SERVER_SOCKET_TIMEOUT_MS || "10000", 10);
  server.maxHeadersCount = 100;

  server.on("connection", (socket) => {
    const ip = normalizeIp(socket.remoteAddress || "unknown");
    const active = (ipConnectionCount.get(ip) || 0) + 1;
    ipConnectionCount.set(ip, active);

    if (!isLocalIp(ip) && active > maxConnectionsPerIp) {
      socket.destroy();
      ipConnectionCount.set(ip, Math.max(0, (ipConnectionCount.get(ip) || 1) - 1));
      return;
    }

    socket.on("close", () => {
      const current = (ipConnectionCount.get(ip) || 1) - 1;
      if (current <= 0) {
        ipConnectionCount.delete(ip);
      } else {
        ipConnectionCount.set(ip, current);
      }
    });
  });
}

function formatUrl(protocol, host, port) {
  const defaultPort = protocol === "https" ? 443 : 80;
  return port === defaultPort ? `${protocol}://${host}` : `${protocol}://${host}:${port}`;
}

function normalizeIp(rawIp) {
  const value = String(rawIp || "").trim();
  if (value.startsWith("::ffff:")) {
    return value.slice(7);
  }

  if (value === "::1") {
    return "127.0.0.1";
  }

  return value || "unknown";
}

function isLocalIp(ip) {
  const value = normalizeIp(ip);
  return value === "127.0.0.1" || value === "localhost";
}

function getRiskState(req) {
  const ip = getRequestIp(req);
  return getRiskStateByIp(ip);
}

function getRiskStateByIp(ip) {
  const normalizedIp = normalizeIp(ip);
  if (!ipRisk.has(normalizedIp)) {
    return null;
  }

  const current = ipRisk.get(normalizedIp);
  const now = Date.now();

  if (now - current.updatedAt > riskDecayMs) {
    current.score = Math.max(0, current.score - 1);
    current.updatedAt = now;
  }

  if (current.score <= 0 && (!current.blockedUntil || current.blockedUntil <= now)) {
    ipRisk.delete(normalizedIp);
    return null;
  }

  return current;
}

function addRisk(req, points, reason) {
  const ip = getRequestIp(req);
  const now = Date.now();
  const normalizedIp = normalizeIp(ip);
  const current =
    getRiskStateByIp(normalizedIp) || { score: 0, blockedUntil: 0, updatedAt: now, reasons: [] };

  current.score += Math.max(1, points);
  current.updatedAt = now;
  current.reasons = [...current.reasons.slice(-6), reason];

  if (enableIpRiskBlock && !isLocalIp(normalizedIp) && current.score >= maxRiskBeforeBlock) {
    const nextBlockUntil = now + riskBlockMs;
    const shouldAuditBlock = !current.blockedUntil || current.blockedUntil < nextBlockUntil;
    current.blockedUntil = nextBlockUntil;

    if (shouldAuditBlock) {
      audit("security.ip_blocked", req, {
        ipHash: createSha256Hex(`${APP_HMAC_SECRET}|ipraw|${normalizedIp}`),
        score: current.score,
        blockedUntil: new Date(current.blockedUntil).toISOString(),
        reason
      });
    }
  }

  ipRisk.set(normalizedIp, current);
}

function reduceRisk(req, points) {
  const ip = getRequestIp(req);
  const current = getRiskStateByIp(ip);
  if (!current) {
    return;
  }

  current.score = Math.max(0, current.score - Math.max(1, points));
  current.updatedAt = Date.now();

  if (current.score === 0 && (!current.blockedUntil || current.blockedUntil <= Date.now())) {
    ipRisk.delete(normalizeIp(ip));
    return;
  }

  ipRisk.set(normalizeIp(ip), current);
}

function clearRisk(req) {
  const ip = getRequestIp(req);
  ipRisk.delete(normalizeIp(ip));
}

function cleanExpiredRiskStates() {
  const now = Date.now();
  for (const [ip, state] of ipRisk.entries()) {
    if (state.blockedUntil && state.blockedUntil > now) {
      continue;
    }

    if (state.score <= 0 || now - state.updatedAt > riskDecayMs * 2) {
      ipRisk.delete(ip);
    }
  }
}
