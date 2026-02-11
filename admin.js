const loginPanel = document.getElementById("loginPanel");
const consolePanel = document.getElementById("consolePanel");
const loginForm = document.getElementById("adminLoginForm");
const adminFeedback = document.getElementById("adminFeedback");
const submissionsView = document.getElementById("submissionsView");
const auditView = document.getElementById("auditView");
const refreshBtn = document.getElementById("refreshBtn");
const logoutBtn = document.getElementById("logoutBtn");

let csrfToken = "";

function setFeedback(message, color = "#9fd0ff") {
  adminFeedback.textContent = message;
  adminFeedback.style.color = color;
}

function showConsole() {
  loginPanel.classList.add("hidden-block");
  consolePanel.classList.remove("hidden-block");
}

function showLogin() {
  consolePanel.classList.add("hidden-block");
  loginPanel.classList.remove("hidden-block");
}

async function ensureBootstrap() {
  const response = await fetch("/api/security/bootstrap", {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json"
    }
  });

  if (!response.ok) {
    throw new Error("Falha ao preparar contexto de segurança.");
  }

  const body = await response.json();
  if (!body?.ok || !body?.csrfToken) {
    throw new Error("Resposta de segurança inválida.");
  }

  csrfToken = body.csrfToken;
}

async function secureRequest(path, options = {}) {
  if (!csrfToken) {
    await ensureBootstrap();
  }

  const headers = {
    Accept: "application/json",
    "X-CSRF-Token": csrfToken,
    ...(options.headers || {})
  };

  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  let response = await fetch(path, {
    ...options,
    credentials: "include",
    headers
  });

  if (response.status === 403) {
    await ensureBootstrap();
    response = await fetch(path, {
      ...options,
      credentials: "include",
      headers: {
        ...headers,
        "X-CSRF-Token": csrfToken
      }
    });
  }

  const body = await response.json().catch(() => ({}));
  return { response, body };
}

function renderJson(element, value) {
  element.textContent = JSON.stringify(value, null, 2);
}

async function refreshConsole() {
  const submissions = await secureRequest("/api/admin/submissions?limit=100", { method: "GET" });
  if (!submissions.response.ok || !submissions.body?.ok) {
    throw new Error(submissions.body?.error || "Falha ao carregar inscrições.");
  }

  const audit = await secureRequest("/api/admin/audit?limit=120", { method: "GET" });
  if (!audit.response.ok || !audit.body?.ok) {
    throw new Error(audit.body?.error || "Falha ao carregar auditoria.");
  }

  renderJson(submissionsView, submissions.body.items || []);
  renderJson(auditView, audit.body.items || []);
}

async function tryRestoreSession() {
  const result = await secureRequest("/api/admin/session", { method: "GET" });
  if (result.response.ok && result.body?.ok) {
    showConsole();
    setFeedback(`Sessão ativa para ${result.body.username}.`, "#9ff7d8");
    await refreshConsole();
    return;
  }

  showLogin();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!loginForm.checkValidity()) {
    loginForm.reportValidity();
    return;
  }

  const data = new FormData(loginForm);
  const username = String(data.get("username") || "").trim();
  const password = String(data.get("password") || "");

  try {
    setFeedback("Autenticando...", "#9fd0ff");

    const { response, body } = await secureRequest("/api/admin/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });

    if (!response.ok || !body?.ok) {
      setFeedback(body?.error || "Falha no login.", "#ffb3c0");
      return;
    }

    showConsole();
    setFeedback("Login confirmado. Carregando painel...", "#9ff7d8");
    loginForm.reset();
    await refreshConsole();
  } catch (error) {
    console.error(error);
    setFeedback("Não foi possível concluir o login.", "#ffb3c0");
  }
});

refreshBtn.addEventListener("click", async () => {
  try {
    setFeedback("Atualizando painel...", "#9fd0ff");
    await refreshConsole();
    setFeedback("Painel atualizado.", "#9ff7d8");
  } catch (error) {
    console.error(error);
    setFeedback("Falha ao atualizar painel.", "#ffb3c0");
  }
});

logoutBtn.addEventListener("click", async () => {
  try {
    const { response } = await secureRequest("/api/admin/logout", { method: "POST" });
    if (!response.ok) {
      setFeedback("Falha ao encerrar sessão.", "#ffb3c0");
      return;
    }

    showLogin();
    renderJson(submissionsView, []);
    renderJson(auditView, []);
    setFeedback("Sessão encerrada.", "#9ff7d8");
  } catch (error) {
    console.error(error);
    setFeedback("Falha ao encerrar sessão.", "#ffb3c0");
  }
});

ensureBootstrap()
  .then(() => tryRestoreSession())
  .catch((error) => {
    console.error(error);
    setFeedback("Falha ao iniciar contexto de segurança.", "#ffb3c0");
    showLogin();
  });
