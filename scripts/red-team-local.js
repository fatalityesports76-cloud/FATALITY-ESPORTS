const https = require("https");

const baseUrl = process.env.TARGET_URL || "https://fatality.local";

async function main() {
  const summary = [];

  summary.push(await testMethodRestriction());
  summary.push(await testMalformedJson());
  summary.push(await testLargePayload());
  summary.push(await testBruteForceLogin());
  summary.push(await testFloodHealth());
  summary.push(await testServiceAvailability());

  console.log("\n=== Red Team Local Report ===");
  for (const item of summary) {
    console.log(`- ${item.name}: ${item.ok ? "OK" : "FAIL"} (${item.detail})`);
  }

  const failed = summary.filter((item) => !item.ok);
  if (failed.length > 0) {
    process.exitCode = 1;
  }
}

async function testMethodRestriction() {
  const response = await rawRequest("/api/healthz", {
    method: "TRACE"
  });

  return {
    name: "TRACE bloqueado",
    ok: response.status === 405,
    detail: `status=${response.status}`
  };
}

async function testMalformedJson() {
  const bootstrap = await getBootstrap();

  const response = await rawRequest("/api/recruitment", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": bootstrap.csrfToken,
      Cookie: bootstrap.cookieHeader
    },
    body: "{invalid-json"
  });

  return {
    name: "JSON malformado",
    ok: response.status === 400,
    detail: `status=${response.status}`
  };
}

async function testLargePayload() {
  const bootstrap = await getBootstrap();
  const hugeText = "A".repeat(45_000);

  const response = await rawRequest("/api/recruitment", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": bootstrap.csrfToken,
      Cookie: bootstrap.cookieHeader
    },
    body: JSON.stringify({
      honeypot: "",
      envelope: {
        version: 1,
        wrappedKey: hugeText,
        iv: "AAAAAAAAAAAAAAAA",
        ciphertext: hugeText
      }
    })
  });

  return {
    name: "Payload gigante",
    ok: response.status === 413 || response.status === 400,
    detail: `status=${response.status}`
  };
}

async function testBruteForceLogin() {
  const bootstrap = await getBootstrap();
  let unauthorizedCount = 0;
  let rateLimitedCount = 0;

  for (let i = 0; i < 14; i += 1) {
    const response = await rawRequest("/api/admin/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": bootstrap.csrfToken,
        Cookie: bootstrap.cookieHeader
      },
      body: JSON.stringify({ username: "admin", password: `wrong_${i}` })
    });

    if (response.status === 401) {
      unauthorizedCount += 1;
    }

    if (response.status === 429) {
      rateLimitedCount += 1;
      break;
    }
  }

  return {
    name: "Brute force login",
    ok: rateLimitedCount > 0,
    detail: `401=${unauthorizedCount},429=${rateLimitedCount}`
  };
}

async function testFloodHealth() {
  const calls = [];
  for (let i = 0; i < 500; i += 1) {
    calls.push(rawRequest("/api/healthz", { method: "GET" }).then((result) => result.status));
  }

  const statuses = await Promise.all(calls);
  const ok200 = statuses.filter((code) => code === 200).length;
  const throttled = statuses.filter((code) => code === 429).length;

  return {
    name: "Flood health endpoint",
    ok: throttled > 0,
    detail: `200=${ok200},429=${throttled}`
  };
}

async function testServiceAvailability() {
  const response = await rawRequest("/", { method: "GET" });

  return {
    name: "Servico permanece online",
    ok: response.status === 200,
    detail: `status=${response.status}`
  };
}

async function getBootstrap() {
  const response = await rawRequest("/api/security/bootstrap", {
    method: "GET",
    headers: { Accept: "application/json" }
  });

  let body = {};
  try {
    body = JSON.parse(response.body || "{}");
  } catch {
    body = {};
  }

  const cookieHeader = (response.setCookie || []).map((line) => line.split(";")[0]).join("; ");

  return {
    csrfToken: body.csrfToken,
    cookieHeader
  };
}

function rawRequest(pathname, options) {
  return new Promise((resolve, reject) => {
    const url = new URL(pathname, baseUrl);
    const request = https.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + (url.search || ""),
        method: options.method || "GET",
        headers: options.headers || {},
        rejectUnauthorized: false
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          resolve({
            status: response.statusCode || 0,
            body: Buffer.concat(chunks).toString("utf8"),
            setCookie: response.headers["set-cookie"] || []
          });
        });
      }
    );

    request.on("error", reject);

    if (options.body) {
      request.write(options.body);
    }

    request.end();
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
