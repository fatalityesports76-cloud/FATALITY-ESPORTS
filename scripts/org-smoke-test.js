const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const APP_DIR = path.resolve(__dirname, "..");
const OWNER_BOOTSTRAP_PATH = path.join(APP_DIR, "secrets", "org-owner-bootstrap.txt");

function delay(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function parseOwnerCredentials() {
  const envUserNumber = String(process.env.ORG_SMOKE_USER_NUMBER || "").trim();
  const envPassword = String(process.env.ORG_SMOKE_PASSWORD || "").trim();
  if (/^[0-9]{4,12}$/.test(envUserNumber) && envPassword.length >= 8) {
    return {
      userNumber: envUserNumber,
      password: envPassword
    };
  }

  if (!fs.existsSync(OWNER_BOOTSTRAP_PATH)) {
    throw new Error(`Arquivo nao encontrado: ${OWNER_BOOTSTRAP_PATH}`);
  }

  const lines = fs
    .readFileSync(OWNER_BOOTSTRAP_PATH, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const ownerLine = [...lines]
    .reverse()
    .find((line) => /Usuario\s+\d+\s+\|\s+Senha\s+/i.test(line));

  if (!ownerLine) {
    throw new Error(
      "Nao foi possivel identificar credenciais de dono em org-owner-bootstrap.txt. " +
        "Defina ORG_SMOKE_USER_NUMBER e ORG_SMOKE_PASSWORD para executar o teste."
    );
  }

  const match = ownerLine.match(/Usuario\s+(\d+)\s+\|\s+Senha\s+(.+)$/i);
  if (!match) {
    throw new Error("Formato invalido das credenciais de dono.");
  }

  return {
    userNumber: match[1].trim(),
    password: match[2].trim()
  };
}

function parseCandidateBaseUrls(logBuffer) {
  const logText = String(logBuffer || "");
  const candidates = [];
  const seen = new Set();

  function push(url) {
    if (!url || seen.has(url)) {
      return;
    }

    seen.add(url);
    candidates.push(url);
  }

  const withPort = logText.match(/https:\/\/fatality\.local:(\d+)/i);
  if (withPort) {
    push(`https://fatality.local:${withPort[1]}`);
  }

  if (/https:\/\/fatality\.local(?!:)/i.test(logText)) {
    push("https://fatality.local");
  }

  push("https://fatality.local:8443");
  push("https://fatality.local");

  return candidates;
}

function createCookieJar() {
  const data = new Map();

  return {
    header() {
      return Array.from(data.entries())
        .map(([name, value]) => `${name}=${value}`)
        .join("; ");
    },
    capture(response) {
      const setCookie = response.headers.getSetCookie ? response.headers.getSetCookie() : [];
      for (const line of setCookie) {
        const first = String(line).split(";")[0];
        const index = first.indexOf("=");
        if (index <= 0) {
          continue;
        }

        const name = first.slice(0, index).trim();
        const value = first.slice(index + 1).trim();
        data.set(name, value);
      }
    }
  };
}

async function requestJson(baseUrl, jar, pathname, options = {}) {
  const headers = {
    Accept: "application/json",
    ...(options.headers || {})
  };

  const cookieHeader = jar.header();
  if (cookieHeader) {
    headers.Cookie = cookieHeader;
  }

  const response = await fetch(`${baseUrl}${pathname}`, {
    ...options,
    headers
  });

  jar.capture(response);
  const body = await response.json().catch(() => ({}));

  return { response, body };
}

async function waitHealth(baseUrl, jar, timeoutMs = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const { response, body } = await requestJson(baseUrl, jar, "/api/healthz", { method: "GET" });
      if (response.ok && body?.ok) {
        return;
      }
    } catch (_error) {
      // keep trying
    }

    await delay(600);
  }

  throw new Error("Servidor nao respondeu no healthcheck.");
}

async function runFlow(baseUrl) {
  const jar = createCookieJar();
  const owner = parseOwnerCredentials();

  await waitHealth(baseUrl, jar);

  const bootstrap = await requestJson(baseUrl, jar, "/api/security/bootstrap", { method: "GET" });
  if (!bootstrap.response.ok || !bootstrap.body?.csrfToken) {
    throw new Error(`Bootstrap falhou: ${JSON.stringify(bootstrap.body)}`);
  }

  const csrfToken = bootstrap.body.csrfToken;

  const login = await requestJson(baseUrl, jar, "/api/org/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken
    },
    body: JSON.stringify({
      userNumber: owner.userNumber,
      password: owner.password
    })
  });

  if (
    login.response.status === 202 &&
    login.body?.ok &&
    login.body?.requiresEmailVerification &&
    login.body?.verificationId
  ) {
    if (!login.body?.debugVerificationCode) {
      throw new Error(
        "ORG_SHOW_DELIVERY_DEBUG deve estar ativo para org:smoke (codigo de login nao retornado)."
      );
    }

    const confirmLogin = await requestJson(baseUrl, jar, "/api/org/login/confirm-email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken
      },
      body: JSON.stringify({
        verificationId: login.body.verificationId,
        code: login.body.debugVerificationCode
      })
    });

    if (!confirmLogin.response.ok || !confirmLogin.body?.ok || !confirmLogin.body?.session) {
      throw new Error(`Confirmacao de login da org falhou: ${JSON.stringify(confirmLogin.body)}`);
    }
  } else if (!login.response.ok || !login.body?.ok || !login.body?.session) {
    throw new Error(`Login de dono falhou: ${JSON.stringify(login.body)}`);
  }

  const stamp = Date.now();
  const directCreate = await requestJson(baseUrl, jar, "/api/org/admin/users/direct-create", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken
    },
    body: JSON.stringify({
      fullName: "Teste Smoke Org",
      email: `smoke.org.${stamp}@example.com`,
      inGameName: `SmokeIgn${String(stamp).slice(-4)}`,
      gameId: String(400000 + (stamp % 500000)),
      serverId: String(8000 + (stamp % 1000)),
      whatsapp: "11999999999",
      role: "staff",
      note: "Fluxo automatizado de teste"
    })
  });

  if (!directCreate.response.ok || !directCreate.body?.ok || !directCreate.body?.userNumber) {
    throw new Error(`Cadastro direto falhou: ${JSON.stringify(directCreate.body)}`);
  }

  const approvedUserNumber = String(directCreate.body?.userNumber || "");
  const temporaryPassword = String(directCreate.body?.temporaryPassword || "");
  if (temporaryPassword) {
    const memberJar = createCookieJar();

    const memberBootstrap = await requestJson(baseUrl, memberJar, "/api/security/bootstrap", { method: "GET" });
    if (!memberBootstrap.response.ok || !memberBootstrap.body?.csrfToken) {
      throw new Error(`Bootstrap do membro falhou: ${JSON.stringify(memberBootstrap.body)}`);
    }

    const memberCsrfToken = memberBootstrap.body.csrfToken;

    const memberLogin = await requestJson(baseUrl, memberJar, "/api/org/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": memberCsrfToken
      },
      body: JSON.stringify({
        userNumber: approvedUserNumber,
        password: temporaryPassword
      })
    });

    if (
      memberLogin.response.status !== 202 ||
      !memberLogin.body?.ok ||
      !memberLogin.body?.requiresEmailVerification ||
      !memberLogin.body?.verificationId ||
      !memberLogin.body?.debugVerificationCode
    ) {
      throw new Error(`Login do membro nao entrou no fluxo de verificacao: ${JSON.stringify(memberLogin.body)}`);
    }

    const confirmMemberLogin = await requestJson(baseUrl, memberJar, "/api/org/login/confirm-email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": memberCsrfToken
      },
      body: JSON.stringify({
        verificationId: memberLogin.body.verificationId,
        code: memberLogin.body.debugVerificationCode
      })
    });

    if (!confirmMemberLogin.response.ok || !confirmMemberLogin.body?.ok || !confirmMemberLogin.body?.session) {
      throw new Error(`Confirmacao de e-mail no login do membro falhou: ${JSON.stringify(confirmMemberLogin.body)}`);
    }

    const changedEmail = `smoke.org.changed.${stamp}@example.com`;
    const emailChangeRequest = await requestJson(baseUrl, memberJar, "/api/org/email/change/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": memberCsrfToken
      },
      body: JSON.stringify({
        currentPassword: temporaryPassword,
        newEmail: changedEmail,
        newEmailConfirm: changedEmail
      })
    });

    if (
      emailChangeRequest.response.status !== 202 ||
      !emailChangeRequest.body?.ok ||
      !emailChangeRequest.body?.verificationId ||
      !emailChangeRequest.body?.debugVerificationCode
    ) {
      throw new Error(`Solicitacao de troca de e-mail falhou: ${JSON.stringify(emailChangeRequest.body)}`);
    }

    const emailChangeConfirm = await requestJson(baseUrl, memberJar, "/api/org/email/change/confirm", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": memberCsrfToken
      },
      body: JSON.stringify({
        verificationId: emailChangeRequest.body.verificationId,
        code: emailChangeRequest.body.debugVerificationCode
      })
    });

    if (!emailChangeConfirm.response.ok || !emailChangeConfirm.body?.ok) {
      throw new Error(`Confirmacao da troca de e-mail falhou: ${JSON.stringify(emailChangeConfirm.body)}`);
    }
  }

  console.log(
    `Org smoke test OK | dono=${owner.userNumber} | userAprovado=${approvedUserNumber}`
  );
}

async function main() {
  const server = spawn(process.execPath, ["server.js"], {
    cwd: APP_DIR,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"]
  });

  let logs = "";
  server.stdout.on("data", (chunk) => {
    logs += chunk.toString("utf8");
  });
  server.stderr.on("data", (chunk) => {
    logs += chunk.toString("utf8");
  });

  try {
    await delay(2500);
    const candidates = parseCandidateBaseUrls(logs);
    let lastError = null;

    for (const baseUrl of candidates) {
      try {
        await runFlow(baseUrl);
        lastError = null;
        break;
      } catch (error) {
        lastError = error;
      }
    }

    if (lastError) {
      throw lastError;
    }
  } finally {
    server.kill("SIGINT");
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
