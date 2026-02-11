const revealItems = document.querySelectorAll(".reveal");
const form = document.getElementById("recruitmentForm");
const feedback = document.getElementById("formFeedback");
const logo = document.getElementById("teamLogo");
const logoHint = document.getElementById("logoHint");
const particleField = document.querySelector("[data-particle-field]");
const phoenixEmitter = document.querySelector("[data-phoenix-emitter]");
const selectionStepButtons = Array.from(document.querySelectorAll("[data-selection-step]"));
const selectionPanels = Array.from(document.querySelectorAll("[data-selection-panel]"));
const selectionProgressFill = document.querySelector("[data-selection-progress-fill]");
const selectionProgressTrack = document.querySelector("[data-selection-progress-track]");
const selectionProgressText = document.querySelector("[data-selection-progress-text]");
const selectionProgressStage = document.querySelector("[data-selection-progress-stage]");
const navHashLinks = Array.from(document.querySelectorAll(".brand-nav a[href^='#']"));
const orgAccessRoot = document.querySelector("[data-org-access]");
const numericOnlyInputs = ["whatsapp", "idJogo", "serverJogo"]
  .map((id) => document.getElementById(id))
  .filter(Boolean);
const supportsMatchMedia = typeof window.matchMedia === "function";
const isCoarsePointer = supportsMatchMedia
  ? window.matchMedia("(hover: none) and (pointer: coarse)").matches
  : false;
const isNarrowViewport = supportsMatchMedia
  ? window.matchMedia("(max-width: 900px)").matches
  : window.innerWidth <= 900;
const hasLowCpuBudget = Number(navigator.hardwareConcurrency || 8) <= 6;
const shouldUseMobilePerformanceMode = isCoarsePointer || (isNarrowViewport && hasLowCpuBudget);

if (shouldUseMobilePerformanceMode) {
  document.documentElement.classList.add("mobile-performance");
  document.body?.classList.add("mobile-performance");
}

const observer = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) {
        return;
      }

      entry.target.classList.add("visible");
      observer.unobserve(entry.target);
    });
  },
  { threshold: 0.16 }
);

revealItems.forEach((item) => observer.observe(item));

if (logo && logoHint) {
  logo.addEventListener("error", () => {
    logo.classList.add("hidden");
    logoHint.classList.remove("hidden");
    if (phoenixEmitter) {
      phoenixEmitter.classList.add("hidden");
    }
  });
}

function createPhoenixSpark() {
  const spark = document.createElement("span");
  spark.className = "phoenix-spark";

  const sx = 44 + Math.random() * 12;
  const sy = 48 + Math.random() * 20;
  const angle = Math.random() * Math.PI * 2;
  const distance = 84 + Math.random() * 190;
  const burstX = Math.cos(angle) * distance;
  const burstY = Math.sin(angle) * distance;

  spark.style.setProperty("--sx", `${sx.toFixed(2)}%`);
  spark.style.setProperty("--sy", `${sy.toFixed(2)}%`);
  spark.style.setProperty("--spark-size", `${(2.4 + Math.random() * 5).toFixed(2)}px`);
  spark.style.setProperty("--spark-delay", `${(-8.2 * Math.random()).toFixed(2)}s`);
  spark.style.setProperty("--spark-duration", `${(2 + Math.random() * 3.6).toFixed(2)}s`);
  spark.style.setProperty("--burst-x", `${burstX.toFixed(2)}px`);
  spark.style.setProperty("--burst-y", `${burstY.toFixed(2)}px`);
  spark.style.setProperty("--spark-glow", `${(0.55 + Math.random() * 0.9).toFixed(2)}`);
  return spark;
}

function initPhoenixEmitter() {
  if (!phoenixEmitter || !logo) {
    return;
  }

  const prefersReducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  if (prefersReducedMotion) {
    return;
  }

  const sparkCount = shouldUseMobilePerformanceMode
    ? 10
    : window.matchMedia?.("(max-width: 760px)").matches
      ? 24
      : 44;
  const fragment = document.createDocumentFragment();

  for (let i = 0; i < sparkCount; i += 1) {
    fragment.appendChild(createPhoenixSpark());
  }

  phoenixEmitter.appendChild(fragment);
}

function createEmberParticle() {
  const particle = document.createElement("span");
  particle.className = "ember";
  particle.style.left = `${(Math.random() * 100).toFixed(2)}%`;
  particle.style.setProperty("--size", `${(2.2 + Math.random() * 5.6).toFixed(2)}px`);
  particle.style.setProperty("--delay", `${(-14 * Math.random()).toFixed(2)}s`);
  particle.style.setProperty("--duration", `${(4.8 + Math.random() * 7.2).toFixed(2)}s`);
  particle.style.setProperty("--drift-x", `${(-40 + Math.random() * 80).toFixed(2)}px`);
  particle.style.setProperty("--glow", (0.5 + Math.random() * 0.85).toFixed(2));
  return particle;
}

function initParticleField() {
  if (!particleField) {
    return;
  }

  const prefersReducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  if (prefersReducedMotion) {
    return;
  }

  const particleCount = shouldUseMobilePerformanceMode
    ? 10
    : window.matchMedia?.("(max-width: 760px)").matches
      ? 34
      : 74;
  const fragment = document.createDocumentFragment();

  for (let i = 0; i < particleCount; i += 1) {
    fragment.appendChild(createEmberParticle());
  }

  particleField.appendChild(fragment);

  if (shouldUseMobilePerformanceMode) {
    particleField.style.setProperty("--scroll-lift", "0px");
    return;
  }

  let ticking = false;

  function applyScrollEffects() {
    const scrollTop = window.scrollY || window.pageYOffset || 0;
    const lift = Math.min(scrollTop * 0.34, 190);
    particleField.style.setProperty("--scroll-lift", `${lift.toFixed(2)}px`);

    ticking = false;
  }

  window.addEventListener(
    "scroll",
    () => {
      if (ticking) {
        return;
      }

      ticking = true;
      window.requestAnimationFrame(applyScrollEffects);
    },
    { passive: true }
  );

  applyScrollEffects();
}

const encoder = new TextEncoder();
let securityContext = null;
const cookieConsentStorageKey = "fatality_cookie_consent_v1";
let cookieConsentOverlay = null;

initParticleField();
initPhoenixEmitter();
initSelectionStepper();
initNavigationHighlight();
initCookieConsent();
initOrgAccess();
initOrgEmailVerificationPage();

function setFeedback(message, color) {
  feedback.textContent = message;
  feedback.style.color = color;
}

function hasCookieConsent() {
  try {
    return window.localStorage?.getItem(cookieConsentStorageKey) === "accepted";
  } catch (_error) {
    return false;
  }
}

function markCookieConsentAccepted() {
  try {
    window.localStorage?.setItem(cookieConsentStorageKey, "accepted");
  } catch (_error) {
    // Se localStorage estiver bloqueado, ainda libera nesta sessão.
  }
}

function clearCookieConsentAccepted() {
  try {
    window.localStorage?.removeItem(cookieConsentStorageKey);
  } catch (_error) {
    // noop
  }
}

function closeCookieConsentOverlay() {
  const body = document.body;
  if (body) {
    body.classList.remove("cookie-consent-lock");
  }
  if (cookieConsentOverlay) {
    cookieConsentOverlay.remove();
    cookieConsentOverlay = null;
  }
}

function openCookieConsentOverlay(fromManager = false) {
  const body = document.body;
  if (!body) {
    return;
  }

  if (cookieConsentOverlay) {
    return;
  }

  const acceptedBeforeOpen = hasCookieConsent();

  const overlay = document.createElement("div");
  overlay.className = "cookie-consent-overlay";
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-label", "Consentimento de cookies");
  cookieConsentOverlay = overlay;

  const box = document.createElement("div");
  box.className = "cookie-consent-box";

  const title = document.createElement("h2");
  title.className = "cookie-consent-title";
  title.textContent = fromManager ? "Gerenciar cookies" : "Uso obrigatório de cookies";

  const text = document.createElement("p");
  text.className = "cookie-consent-text";
  text.textContent = fromManager
    ? "Gerencie seu consentimento de cookies do site. Para continuar usando o sistema com sessão e segurança, o consentimento deve estar aceito."
    : "Para acessar este site e o painel da organização, você precisa aceitar os cookies de segurança, sessão e desempenho.";

  const links = document.createElement("p");
  links.className = "cookie-consent-links";
  const consentLinks = [
    { href: "/termos", text: "Termos" },
    { href: "/politica", text: "Política" },
    { href: "/privacidade", text: "Privacidade" }
  ];
  consentLinks.forEach((item, index) => {
    if (index > 0) {
      links.appendChild(document.createTextNode(" • "));
    }
    const anchor = document.createElement("a");
    anchor.href = item.href;
    anchor.target = "_blank";
    anchor.rel = "noopener noreferrer";
    anchor.textContent = item.text;
    links.appendChild(anchor);
  });

  const actions = document.createElement("div");
  actions.className = "cookie-consent-actions";

  const acceptBtn = document.createElement("button");
  acceptBtn.type = "button";
  acceptBtn.className = "btn btn-primary cookie-consent-accept";
  acceptBtn.textContent = "Aceitar cookies e continuar";
  acceptBtn.addEventListener("click", () => {
    markCookieConsentAccepted();
    closeCookieConsentOverlay();
  });
  actions.appendChild(acceptBtn);

  if (fromManager && acceptedBeforeOpen) {
    const revokeBtn = document.createElement("button");
    revokeBtn.type = "button";
    revokeBtn.className = "btn btn-secondary cookie-consent-revoke";
    revokeBtn.textContent = "Revogar consentimento";
    revokeBtn.addEventListener("click", () => {
      clearCookieConsentAccepted();
      text.textContent =
        "Consentimento revogado. Para continuar usando o site com sessão e segurança, aceite novamente os cookies.";
      revokeBtn.disabled = true;
    });
    actions.appendChild(revokeBtn);
  }

  box.appendChild(title);
  box.appendChild(text);
  box.appendChild(links);
  box.appendChild(actions);
  overlay.appendChild(box);

  body.classList.add("cookie-consent-lock");
  body.appendChild(overlay);
}

function ensureCookieManagerButtons() {
  const footerLinks = document.querySelectorAll(".footer-links");
  footerLinks.forEach((container) => {
    if (container.querySelector("[data-cookie-manage]")) {
      return;
    }

    const separator = document.createElement("span");
    separator.textContent = "|";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "cookie-manage-btn";
    button.dataset.cookieManage = "true";
    button.textContent = "Gerenciar cookies";

    container.appendChild(separator);
    container.appendChild(button);
  });
}

function ensureCookieManagerNavButtons() {
  const navBlocks = document.querySelectorAll(".brand-nav");
  navBlocks.forEach((container) => {
    if (container.querySelector("[data-cookie-manage-nav]")) {
      return;
    }

    const button = document.createElement("button");
    button.type = "button";
    button.className = "cookie-manage-nav-btn";
    button.dataset.cookieManage = "true";
    button.dataset.cookieManageNav = "true";
    button.textContent = "Cookies";
    container.appendChild(button);
  });
}

function bindCookieManagerButtons() {
  const buttons = document.querySelectorAll("[data-cookie-manage]");
  buttons.forEach((button) => {
    if (button.dataset.cookieManageBound === "true") {
      return;
    }
    button.dataset.cookieManageBound = "true";
    button.addEventListener("click", () => {
      openCookieConsentOverlay(true);
    });
  });
}

function initCookieConsent() {
  ensureCookieManagerButtons();
  ensureCookieManagerNavButtons();
  bindCookieManagerButtons();
  if (!hasCookieConsent()) {
    openCookieConsentOverlay(false);
  }
}

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

async function loadSecurityContext(forceRefresh = false) {
  if (securityContext && !forceRefresh) {
    return securityContext;
  }

  const response = await fetch("/api/security/bootstrap", {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json"
    }
  });

  if (!response.ok) {
    const samePath = window.location.pathname || "/";
    const suggestedUrl = `https://127.0.0.1${samePath}`;
    throw new Error(
      `Não foi possível iniciar o contexto de segurança (HTTP ${response.status}). ` +
        `Abra pelo backend em ${suggestedUrl} (não use Live Server :5500).`
    );
  }

  const data = await response
    .json()
    .catch(() => {
      const samePath = window.location.pathname || "/";
      const suggestedUrl = `https://127.0.0.1${samePath}`;
      throw new Error(
        "Resposta de segurança inválida. " +
          "Isso acontece quando o site está em um servidor sem a API (/api). " +
          `Abra pelo backend em ${suggestedUrl} (não use Live Server :5500).`
      );
    });
  if (!data?.ok || !data?.csrfToken || !data?.crypto?.publicKeySpkiBase64) {
    const samePath = window.location.pathname || "/";
    const suggestedUrl = `https://127.0.0.1${samePath}`;
    throw new Error(
      "Resposta de segurança inválida. " +
        `Abra pelo backend em ${suggestedUrl} (não use Live Server :5500).`
    );
  }

  const publicKey = await window.crypto.subtle.importKey(
    "spki",
    fromBase64(data.crypto.publicKeySpkiBase64),
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    false,
    ["encrypt"]
  );

  securityContext = {
    csrfToken: data.csrfToken,
    publicKey,
    keyId: data.crypto.keyId || "v1"
  };

  return securityContext;
}

async function encryptSubmission(publicKey, payload) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const aesKey = await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt"]
  );

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    aesKey,
    encoder.encode(JSON.stringify(payload))
  );

  const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);

  const wrappedKey = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    rawAesKey
  );

  return {
    version: 1,
    wrappedKey: toBase64(wrappedKey),
    iv: toBase64(iv.buffer),
    ciphertext: toBase64(ciphertext)
  };
}

function getString(formData, name) {
  return String(formData.get(name) || "").trim();
}

function collectFormPayload(formData) {
  return {
    jogo: "Mobile Legends",
    nomeCompleto: getString(formData, "nomeCompleto"),
    nickInGame: getString(formData, "nickInGame"),
    eloMaximo: getString(formData, "eloMaximo"),
    wrRanked: Number.parseFloat(getString(formData, "wrRanked")),
    maximoEstrelas: Number.parseInt(getString(formData, "maximoEstrelas"), 10),
    rotaPrincipal: getString(formData, "rotaPrincipal"),
    horarioDisponivel: getString(formData, "horarioDisponivel"),
    identificacaoGenero: getString(formData, "identificacaoGenero"),
    discord: getString(formData, "discord"),
    idJogo: getString(formData, "idJogo"),
    serverJogo: getString(formData, "serverJogo"),
    whatsapp: getString(formData, "whatsapp"),
    enviadoEm: new Date().toISOString()
  };
}

function setActiveSelectionStep(stepKey, shouldFocus = false) {
  if (!stepKey || !selectionStepButtons.length || !selectionPanels.length) {
    return;
  }

  let activeIndex = 0;

  selectionStepButtons.forEach((button, index) => {
    const isActive = button.dataset.selectionStep === stepKey;
    button.classList.toggle("is-active", isActive);
    button.setAttribute("aria-selected", isActive ? "true" : "false");
    button.tabIndex = isActive ? 0 : -1;

    if (isActive && shouldFocus) {
      button.focus();
    }

    if (isActive) {
      activeIndex = index;
    }
  });

  selectionPanels.forEach((panel) => {
    const isActive = panel.dataset.selectionPanel === stepKey;
    panel.classList.toggle("is-active", isActive);
    panel.hidden = !isActive;
  });

  if (selectionProgressFill && selectionProgressTrack) {
    const totalSteps = selectionStepButtons.length;
    const progress = Math.round(((activeIndex + 1) / totalSteps) * 100);
    selectionProgressFill.style.width = `${progress}%`;
    selectionProgressTrack.setAttribute("aria-valuenow", String(progress));

    if (selectionProgressText) {
      selectionProgressText.textContent = `${progress}%`;
    }

    if (selectionProgressStage) {
      const activeStepLabel =
        selectionStepButtons[activeIndex]?.querySelector(".selection-name")?.textContent?.trim() ||
        "";
      selectionProgressStage.textContent = activeStepLabel;
    }
  }
}

function initSelectionStepper() {
  if (!selectionStepButtons.length || !selectionPanels.length) {
    return;
  }

  const activeButton =
    selectionStepButtons.find((button) => button.classList.contains("is-active")) ||
    selectionStepButtons[0];

  setActiveSelectionStep(activeButton.dataset.selectionStep);

  function focusStepByOffset(currentIndex, offset) {
    const total = selectionStepButtons.length;
    const nextIndex = (currentIndex + offset + total) % total;
    const nextStep = selectionStepButtons[nextIndex];
    setActiveSelectionStep(nextStep.dataset.selectionStep, true);
  }

  selectionStepButtons.forEach((button, index) => {
    button.addEventListener("click", () => {
      setActiveSelectionStep(button.dataset.selectionStep);
    });

    button.addEventListener("keydown", (event) => {
      switch (event.key) {
        case "ArrowRight":
        case "ArrowDown":
          event.preventDefault();
          focusStepByOffset(index, 1);
          break;
        case "ArrowLeft":
        case "ArrowUp":
          event.preventDefault();
          focusStepByOffset(index, -1);
          break;
        case "Home":
          event.preventDefault();
          setActiveSelectionStep(selectionStepButtons[0].dataset.selectionStep, true);
          break;
        case "End":
          event.preventDefault();
          setActiveSelectionStep(
            selectionStepButtons[selectionStepButtons.length - 1].dataset.selectionStep,
            true
          );
          break;
        case " ":
        case "Enter":
          event.preventDefault();
          setActiveSelectionStep(button.dataset.selectionStep);
          break;
        default:
          break;
      }
    });
  });
}

function initNavigationHighlight() {
  if (!navHashLinks.length) {
    return;
  }

  const sectionMap = navHashLinks
    .map((link) => {
      const hash = link.getAttribute("href") || "";
      const id = hash.startsWith("#") ? hash.slice(1) : "";
      if (!id) {
        return null;
      }

      const section = document.getElementById(id);
      if (!section) {
        return null;
      }

      return { link, section };
    })
    .filter(Boolean);

  if (!sectionMap.length) {
    return;
  }

  function setActiveNav(link) {
    sectionMap.forEach((item) => {
      item.link.classList.toggle("is-active", item.link === link);
    });
  }

  function updateByScroll() {
    const threshold = window.innerHeight * 0.28;
    let active = sectionMap[0];

    sectionMap.forEach((item) => {
      const top = item.section.getBoundingClientRect().top;
      if (top <= threshold) {
        active = item;
      }
    });

    setActiveNav(active.link);
  }

  navHashLinks.forEach((link) => {
    link.addEventListener("click", () => {
      setActiveNav(link);
    });
  });

  let framePending = false;

  function queueUpdate() {
    if (framePending) {
      return;
    }

    framePending = true;
    window.requestAnimationFrame(() => {
      framePending = false;
      updateByScroll();
    });
  }

  window.addEventListener("scroll", queueUpdate, { passive: true });
  window.addEventListener("resize", queueUpdate, { passive: true });
  queueUpdate();
}

function initOrgAccess() {
  if (!orgAccessRoot) {
    return;
  }

  const orgToggle = orgAccessRoot.querySelector("[data-org-toggle]");
  const orgPanel = orgAccessRoot.querySelector("[data-org-panel]");
  const orgModeSwitch = orgAccessRoot.querySelector(".org-mode-switch");
  const orgModeButtons = Array.from(orgAccessRoot.querySelectorAll("[data-org-mode-btn]"));
  const orgModePanels = Array.from(orgAccessRoot.querySelectorAll("[data-org-mode-panel]"));
  const orgLoginForm = orgAccessRoot.querySelector("[data-org-login-form]");
  const orgLoginVerifyForm = orgAccessRoot.querySelector("[data-org-login-verify-form]");
  const orgLoginVerificationIdInput = orgAccessRoot.querySelector("[data-org-login-verification-id]");
  const orgLoginVerifyLead = orgAccessRoot.querySelector("[data-org-login-verify-lead]");
  const orgLoginVerifyBack = orgAccessRoot.querySelector("[data-org-login-verify-back]");
  const orgRegisterForm = orgAccessRoot.querySelector("[data-org-register-form]");
  const orgDirectCreateForm = orgAccessRoot.querySelector("[data-org-direct-create-form]");
  const orgState = orgAccessRoot.querySelector("[data-org-state]");
  const orgLogout = orgAccessRoot.querySelector("[data-org-logout]");
  const orgChip = orgAccessRoot.querySelector("[data-org-chip]");
  const orgOwnerTools = orgAccessRoot.querySelector("[data-org-owner-tools]");
  const orgOwnerList = orgAccessRoot.querySelector("[data-org-owner-list]");
  const orgOwnerRefresh = orgAccessRoot.querySelector("[data-org-owner-refresh]");
  const orgMembersList = orgAccessRoot.querySelector("[data-org-members-list]");
  const orgMembersRefresh = orgAccessRoot.querySelector("[data-org-members-refresh]");
  const orgAdminDashboard = orgAccessRoot.querySelector("[data-org-admin-dashboard]");
  const orgKpiTotal = orgAccessRoot.querySelector("[data-org-kpi-total]");
  const orgKpiVerified = orgAccessRoot.querySelector("[data-org-kpi-verified]");
  const orgKpiPending = orgAccessRoot.querySelector("[data-org-kpi-pending]");
  const orgKpiLeadership = orgAccessRoot.querySelector("[data-org-kpi-leadership]");
  const orgMemberSearchInput = orgAccessRoot.querySelector("[data-org-member-search]");
  const orgMemberFilterRole = orgAccessRoot.querySelector("[data-org-member-filter-role]");
  const orgMemberFilterEmail = orgAccessRoot.querySelector("[data-org-member-filter-email]");
  const orgMemberClearFilters = orgAccessRoot.querySelector("[data-org-member-clear-filters]");
  const orgAdvancedOps = orgAccessRoot.querySelector("[data-org-advanced-ops]");
  const orgOwnerTarget = orgAccessRoot.querySelector("[data-org-owner-target]");
  const orgOwnerAssume = orgAccessRoot.querySelector("[data-org-owner-assume]");
  const orgOwnerForceReset = orgAccessRoot.querySelector("[data-org-owner-force-reset]");
  const orgOwnerNewCredential = orgAccessRoot.querySelector("[data-org-owner-new-credential]");
  const orgOwnerChangeCredential = orgAccessRoot.querySelector("[data-org-owner-change-credential]");
  const orgPasswordChange = orgAccessRoot.querySelector("[data-org-password-change]");
  const orgPasswordChangeForm = orgAccessRoot.querySelector("[data-org-password-change-form]");
  const orgRegisterReview = orgAccessRoot.querySelector("[data-org-register-review]");
  const orgRegisterReviewContent = orgAccessRoot.querySelector("[data-org-register-review-content]");
  const orgRegisterAccept = orgAccessRoot.querySelector("[data-org-register-accept]");
  const orgRegisterReject = orgAccessRoot.querySelector("[data-org-register-reject]");
  const orgMemberData = orgAccessRoot.querySelector("[data-org-member-data]");
  const orgMemberDataRefresh = orgAccessRoot.querySelector("[data-org-member-data-refresh]");
  const orgMemberSelfList = orgAccessRoot.querySelector("[data-org-member-self-list]");
  const orgMemberUsersList = orgAccessRoot.querySelector("[data-org-member-users-list]");
  const orgMemberRequestsList = orgAccessRoot.querySelector("[data-org-member-requests-list]");
  const orgMemberPreregList = orgAccessRoot.querySelector("[data-org-member-prereg-list]");
  const orgPerformanceShell = orgAccessRoot.querySelector("[data-org-performance-shell]");
  const orgPerformanceRefresh = orgAccessRoot.querySelector("[data-org-performance-refresh]");
  const orgPerformanceTitle = orgAccessRoot.querySelector("[data-org-performance-title]");
  const orgPerformancePicker = orgAccessRoot.querySelector("[data-org-performance-picker]");
  const orgPerformancePlayerSelect = orgAccessRoot.querySelector("[data-org-performance-player-select]");
  const orgPerformanceSummary = orgAccessRoot.querySelector("[data-org-performance-summary]");
  const orgPerformanceEditor = orgAccessRoot.querySelector("[data-org-performance-editor]");
  const orgPerformanceForm = orgAccessRoot.querySelector("[data-org-performance-form]");
  const orgPerformancePlayerInput = orgAccessRoot.querySelector("[data-org-performance-player-input]");
  const orgPerformanceScores = orgAccessRoot.querySelector("[data-org-performance-scores]");
  const orgPerformanceWeekly = orgAccessRoot.querySelector("[data-org-performance-weekly]");
  const orgPerformanceHint = orgAccessRoot.querySelector("[data-org-performance-hint]");
  const orgPerformanceRanking = orgAccessRoot.querySelector("[data-org-performance-ranking]");
  const orgEmailChange = orgAccessRoot.querySelector("[data-org-email-change]");
  const orgEmailCurrent = orgAccessRoot.querySelector("[data-org-email-current]");
  const orgEmailChangeRequestBox = orgAccessRoot.querySelector("[data-org-email-change-request]");
  const orgEmailChangeConfirmBox = orgAccessRoot.querySelector("[data-org-email-change-confirm]");
  const orgEmailChangeRequestForm = orgAccessRoot.querySelector("[data-org-email-change-request-form]");
  const orgEmailChangeConfirmForm = orgAccessRoot.querySelector("[data-org-email-change-confirm-form]");
  const orgEmailChangeVerificationIdInput = orgAccessRoot.querySelector(
    "[data-org-email-change-verification-id]"
  );
  const orgEmailChangeCancel = orgAccessRoot.querySelector("[data-org-email-change-cancel]");
  const orgMemberEditModal = document.querySelector("[data-org-member-edit-modal]");
  const orgMemberEditForm = document.querySelector("[data-org-member-edit-form]");
  const orgMemberEditLead = document.querySelector("[data-org-member-edit-lead]");
  const orgMemberEditCancelButtons = Array.from(
    document.querySelectorAll("[data-org-member-edit-cancel]")
  );
  const isOrgPage = orgAccessRoot.hasAttribute("data-org-page");

  if (
    !orgToggle ||
    !orgPanel ||
    !orgState ||
    !orgLogout ||
    !orgLoginForm ||
    !orgLoginVerifyForm ||
    !orgLoginVerificationIdInput ||
    !orgPasswordChangeForm ||
    !orgEmailChangeRequestForm ||
    !orgEmailChangeConfirmForm ||
    !orgEmailChangeVerificationIdInput
  ) {
    return;
  }

  const roleLabels = {
    player: "Player",
    vice_lider: "Vice-líder",
    staff: "Staff",
    lider: "Líder",
    adm: "ADM",
    dono: "Dono"
  };
  const identificationLabels = {
    "Homem cisgenero": "Homem cisgênero",
    "Mulher cisgenero": "Mulher cisgênero",
    "Homem trans": "Homem trans",
    "Mulher trans": "Mulher trans",
    Transexual: "Transexual",
    Travesti: "Travesti",
    "Nao binario": "Não binário",
    "Genero fluido": "Gênero fluido",
    Agenero: "Agênero",
    Intersexo: "Intersexo",
    Outro: "Outro",
    "Prefiro nao informar": "Prefiro não informar"
  };

  const approvalRoles = new Set(["dono", "lider", "vice_lider", "adm"]);
  const fullManagementRoles = new Set(["dono", "lider"]);
  const performanceEditorRoles = new Set(["dono", "lider", "vice_lider", "adm", "staff"]);
  const performanceCategories = [
    { key: "disciplina", label: "Disciplina" },
    { key: "comunicacao", label: "Comunicação" },
    { key: "macro", label: "Macro" },
    { key: "micro", label: "Micro" },
    { key: "mentalidade", label: "Mentalidade" },
    { key: "disponibilidade", label: "Disponibilidade" }
  ];
  const roleDisplayOrder = ["dono", "lider", "vice_lider", "adm", "staff", "player"];

  const roleClassList = [
    "role-player",
    "role-vice_lider",
    "role-staff",
    "role-lider",
    "role-adm",
    "role-dono"
  ];
  let currentSession = null;
  let pendingRegisterPayload = null;
  let pendingLoginVerificationId = "";
  let performanceSelectedPlayer = "";
  let performanceBoardMode = "";
  let performanceCurrentWeek = "";
  let performanceBoardSnapshot = null;
  let performanceEventSource = null;
  let performanceEventReconnectTimer = null;
  let performanceReloadTimer = null;
  let orgAuthInFlight = false;
  let orgSessionVersion = 0;
  let memberStatusSnapshot = [];

  function isApprovalRole(role) {
    return approvalRoles.has(String(role || ""));
  }

  function isFullManagementRole(role) {
    return fullManagementRoles.has(String(role || ""));
  }

  function assignableRolesForRole(role) {
    switch (String(role || "")) {
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

  function setState(message, color = "") {
    orgState.textContent = message;
    orgState.style.color = color;
  }

  function closePanel() {
    if (isOrgPage) {
      orgPanel.classList.remove("hidden");
      orgToggle.setAttribute("aria-expanded", "true");
      return;
    }

    orgPanel.classList.add("hidden");
    orgToggle.setAttribute("aria-expanded", "false");
  }

  function openPanel() {
    orgPanel.classList.remove("hidden");
    orgToggle.setAttribute("aria-expanded", "true");
  }

  function roleClassName(role) {
    switch (role) {
      case "player":
        return "role-player";
      case "vice_lider":
        return "role-vice_lider";
      case "staff":
        return "role-staff";
      case "lider":
        return "role-lider";
      case "adm":
        return "role-adm";
      case "dono":
        return "role-dono";
      default:
        return "";
    }
  }

  function setMode(modeKey) {
    orgModeButtons.forEach((button) => {
      button.classList.toggle("is-active", button.dataset.orgModeBtn === modeKey);
    });

    orgModePanels.forEach((panel) => {
      const isActivePanel = panel.dataset.orgModePanel === modeKey;
      panel.classList.toggle("hidden", !isActivePanel);
      panel.hidden = !isActivePanel;
    });

    if (modeKey !== "register") {
      pendingRegisterPayload = null;
      if (orgRegisterReview) {
        orgRegisterReview.classList.add("hidden");
        orgRegisterReview.hidden = true;
      }
      if (orgRegisterForm) {
        orgRegisterForm.classList.remove("hidden");
        orgRegisterForm.hidden = false;
      }
      if (orgRegisterReviewContent) {
        orgRegisterReviewContent.innerHTML = "";
      }
    }
  }

  function roleLabelFromValue(roleValue) {
    if (roleValue === "sem_cargo") {
      return "Sem cargo definido";
    }
    return roleLabels[roleValue] || roleValue || "-";
  }

  function identificationLabelFromValue(value) {
    return identificationLabels[String(value || "").trim()] || value || "Prefiro não informar";
  }

  function normalizeRoleValue(value) {
    const normalized = String(value || "").trim().toLowerCase();
    return normalized || "sem_cargo";
  }

  function roleOrderIndex(role) {
    const index = roleDisplayOrder.indexOf(role);
    return index === -1 ? Number.MAX_SAFE_INTEGER : index;
  }

  function sortedRoleKeysFromMap(groups) {
    return Array.from(groups.keys()).sort((a, b) => {
      const orderDiff = roleOrderIndex(a) - roleOrderIndex(b);
      if (orderDiff !== 0) {
        return orderDiff;
      }
      return roleLabelFromValue(a).localeCompare(roleLabelFromValue(b), "pt-BR");
    });
  }

  function createRoleGroupBlock(role, total, unitLabel) {
    const block = document.createElement("section");
    block.className = "org-role-group";
    const roleClass = roleClassName(role);
    if (roleClass) {
      block.classList.add(roleClass);
    }

    const head = document.createElement("div");
    head.className = "org-role-group-head";

    const title = document.createElement("p");
    title.className = "org-role-group-title";
    title.textContent = roleLabelFromValue(role);

    const count = document.createElement("span");
    count.className = "org-role-group-count";
    const suffix = total === 1 ? "" : "s";
    count.textContent = `${total} ${unitLabel}${suffix}`;

    head.appendChild(title);
    head.appendChild(count);

    const list = document.createElement("div");
    list.className = "org-role-group-list";

    block.appendChild(head);
    block.appendChild(list);

    return { block, list };
  }

  function renderRegisterReview(payload) {
    const details = [
      ["Nome completo", payload.fullName],
      ["Email", payload.email],
      ["Nome no jogo", payload.inGameName],
      ["ID", payload.gameId],
      ["ID do servidor", payload.serverId],
      ["Função no time", roleLabelFromValue(payload.desiredRole)],
      ["Identificação", identificationLabelFromValue(payload.identificacaoGenero)],
      ["Observação", payload.note || "-"]
    ];

    orgRegisterReviewContent.innerHTML = "";
    details.forEach(([label, value]) => {
      const row = document.createElement("article");
      row.className = "org-register-review-row";

      const key = document.createElement("p");
      key.className = "org-register-review-key";
      key.textContent = label;

      const val = document.createElement("p");
      val.className = "org-register-review-value";
      val.textContent = value;

      row.appendChild(key);
      row.appendChild(val);
      orgRegisterReviewContent.appendChild(row);
    });
  }

  function setLoginVerifyLead(email) {
    if (!orgLoginVerifyLead) {
      return;
    }

    const normalizedEmail = String(email || "").trim().toLowerCase();
    if (!normalizedEmail) {
      orgLoginVerifyLead.textContent = "Digite o código de e-mail para concluir o login.";
      return;
    }

    orgLoginVerifyLead.textContent =
      `Digite o código de 6 dígitos enviado para ${normalizedEmail} para concluir o login.`;
  }

  function resetEmailChangeFlow() {
    if (orgEmailChangeRequestForm) {
      orgEmailChangeRequestForm.reset();
    }

    if (orgEmailChangeConfirmForm) {
      orgEmailChangeConfirmForm.reset();
    }

    if (orgEmailChangeVerificationIdInput) {
      orgEmailChangeVerificationIdInput.value = "";
    }

    if (orgEmailChangeRequestBox) {
      orgEmailChangeRequestBox.classList.remove("hidden");
      orgEmailChangeRequestBox.hidden = false;
    }

    if (orgEmailChangeConfirmBox) {
      orgEmailChangeConfirmBox.classList.add("hidden");
      orgEmailChangeConfirmBox.hidden = true;
    }
  }

  async function secureOrgRequest(path, options = {}) {
    let context = await loadSecurityContext();
    const headers = {
      Accept: "application/json",
      ...(options.headers || {})
    };

    if (options.body && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }

    headers["X-CSRF-Token"] = context.csrfToken;

    let response = await fetch(path, {
      ...options,
      credentials: "include",
      headers
    });

    if (response.status === 403) {
      context = await loadSecurityContext(true);
      response = await fetch(path, {
        ...options,
        credentials: "include",
        headers: {
          ...headers,
          "X-CSRF-Token": context.csrfToken
        }
      });
    }

    const body = await response.json().catch(() => ({}));

    if (response.status === 401 && currentSession && !orgAuthInFlight) {
      currentSession = null;
      resetAllForms();
      applySession(null);
      const sessionExpiredMessage = "Sessão da org expirada ou não encontrada. Faça login novamente.";
      setState(sessionExpiredMessage, "#ffcf9f");
      return {
        response,
        body: {
          ...body,
          error: sessionExpiredMessage
        }
      };
    }

    return { response, body };
  }

  function sanitizeNumericInputs(scopeElement) {
    const numericInputs = Array.from(scopeElement.querySelectorAll("input[inputmode='numeric']"));
    numericInputs.forEach((input) => {
      input.addEventListener("input", () => {
        const digits = input.value.replace(/\D+/g, "");
        if (input.value !== digits) {
          input.value = digits;
        }
      });
    });
  }

  function resetAllForms() {
    orgLoginForm.reset();
    orgLoginVerifyForm.reset();
    if (orgRegisterForm) {
      orgRegisterForm.reset();
    }
    if (orgDirectCreateForm) {
      orgDirectCreateForm.reset();
    }
    pendingRegisterPayload = null;
    pendingLoginVerificationId = "";
    orgLoginVerificationIdInput.value = "";
    setLoginVerifyLead("");
    if (orgRegisterReview) {
      orgRegisterReview.classList.add("hidden");
      orgRegisterReview.hidden = true;
    }
    if (orgRegisterForm) {
      orgRegisterForm.classList.remove("hidden");
      orgRegisterForm.hidden = false;
    }
    if (orgRegisterReviewContent) {
      orgRegisterReviewContent.innerHTML = "";
    }
    resetEmailChangeFlow();
  }

  function renderOwnerRequests(items) {
    if (!orgOwnerList) {
      return;
    }

    orgOwnerList.innerHTML = "";

    if (!Array.isArray(items) || items.length === 0) {
      const empty = document.createElement("p");
      empty.className = "org-owner-empty";
      empty.textContent = "Nenhum cadastro pendente no momento.";
      orgOwnerList.appendChild(empty);
      return;
    }

    const groupedByRole = new Map();
    items.forEach((item) => {
      const role = normalizeRoleValue(item.desiredRole || item.finalRole || item.role);
      if (!groupedByRole.has(role)) {
        groupedByRole.set(role, []);
      }
      groupedByRole.get(role).push(item);
    });

    const orderedRoles = sortedRoleKeysFromMap(groupedByRole);
    orderedRoles.forEach((role) => {
      const list = groupedByRole.get(role) || [];
      const { block, list: roleList } = createRoleGroupBlock(role, list.length, "pendência");

      list.forEach((item) => {
        const wrapper = document.createElement("article");
        wrapper.className = "org-owner-item";

        const info = document.createElement("div");
        info.className = "org-owner-request-info";

        const fields = [
          ["Nome", item.fullName || "-"],
          ["Função", roleLabelFromValue(item.desiredRole)],
          ["Identificação", identificationLabelFromValue(item.identificacaoGenero)],
          ["Email", item.email || "-"],
          ["Nome no jogo", item.inGameName || "-"],
          ["ID", item.gameId || "-"],
          ["Server", item.serverId || "-"],
          ["Status", item.status || "pending"],
          ["Observação", item.note || "-"]
        ];

        fields.forEach(([label, value]) => {
          const line = document.createElement("p");
          const labelNode = document.createElement("strong");
          labelNode.textContent = `${label}: `;
          line.appendChild(labelNode);
          line.appendChild(document.createTextNode(String(value)));
          info.appendChild(line);
        });

        const actions = document.createElement("div");
        actions.className = "org-owner-actions";

        const approveBtn = document.createElement("button");
        approveBtn.className = "btn btn-primary";
        approveBtn.type = "button";
        approveBtn.dataset.requestId = item.id;
        approveBtn.dataset.action = "approve";
        approveBtn.dataset.role = item.desiredRole;
        approveBtn.textContent = "Aprovar";

        const rejectBtn = document.createElement("button");
        rejectBtn.className = "btn btn-secondary";
        rejectBtn.type = "button";
        rejectBtn.dataset.requestId = item.id;
        rejectBtn.dataset.action = "reject";
        rejectBtn.textContent = "Reprovar";

        actions.appendChild(approveBtn);
        actions.appendChild(rejectBtn);
        wrapper.appendChild(info);
        wrapper.appendChild(actions);
        roleList.appendChild(wrapper);
      });

      orgOwnerList.appendChild(block);
    });
  }

  function updateAdminDashboardMetrics(items) {
    if (!orgAdminDashboard) {
      return;
    }

    const list = Array.isArray(items) ? items : [];
    const total = list.length;
    const verified = list.filter((item) => item && item.emailVerifiedAt).length;
    const pending = Math.max(0, total - verified);
    const leadership = list.filter((item) => {
      const role = String(item?.role || "");
      return role === "dono" || role === "lider" || role === "vice_lider" || role === "adm";
    }).length;

    if (orgKpiTotal) {
      orgKpiTotal.textContent = String(total);
    }
    if (orgKpiVerified) {
      orgKpiVerified.textContent = String(verified);
    }
    if (orgKpiPending) {
      orgKpiPending.textContent = String(pending);
    }
    if (orgKpiLeadership) {
      orgKpiLeadership.textContent = String(leadership);
    }
  }

  function getFilteredMemberStatuses(items) {
    const list = Array.isArray(items) ? items : [];
    const search = String(orgMemberSearchInput?.value || "")
      .trim()
      .toLowerCase();
    const roleFilter = String(orgMemberFilterRole?.value || "").trim().toLowerCase();
    const emailFilter = String(orgMemberFilterEmail?.value || "").trim().toLowerCase();

    return list.filter((item) => {
      if (!item) {
        return false;
      }

      if (roleFilter && String(item.role || "").toLowerCase() !== roleFilter) {
        return false;
      }

      if (emailFilter === "verified" && !item.emailVerifiedAt) {
        return false;
      }
      if (emailFilter === "pending" && item.emailVerifiedAt) {
        return false;
      }

      if (!search) {
        return true;
      }

      const searchable = [
        item.userNumber,
        item.credentialNumber,
        item.fullName,
        item.email,
        item.inGameName,
        item.gameId,
        item.serverId,
        item.whatsapp
      ]
        .map((value) => String(value || "").toLowerCase())
        .join(" ");
      return searchable.includes(search);
    });
  }

  function getMemberByUserNumber(userNumber) {
    const target = String(userNumber || "").trim();
    if (!target) {
      return null;
    }
    return memberStatusSnapshot.find((item) => String(item?.userNumber || "").trim() === target) || null;
  }

  function canEditMemberProfile(item) {
    const actorRole = String(currentSession?.role || "");
    if (!isApprovalRole(actorRole)) {
      return false;
    }

    const targetRole = String(item?.role || "");
    const actorAssignableRoles = new Set(assignableRolesForRole(actorRole));
    return actorAssignableRoles.has(targetRole);
  }

  function openMemberEditModal(item) {
    if (!orgMemberEditModal || !orgMemberEditForm || !item) {
      return;
    }

    const userNumber = String(item.userNumber || "");
    orgMemberEditForm.reset();
    orgMemberEditForm.querySelector("input[name='userNumber']").value = userNumber;
    orgMemberEditForm.querySelector("input[name='fullName']").value = String(item.fullName || "");
    orgMemberEditForm.querySelector("input[name='email']").value = String(item.email || "");
    orgMemberEditForm.querySelector("input[name='inGameName']").value = String(item.inGameName || "");
    orgMemberEditForm.querySelector("input[name='gameId']").value = String(item.gameId || "");
    orgMemberEditForm.querySelector("input[name='serverId']").value = String(item.serverId || "");
    orgMemberEditForm.querySelector("input[name='whatsapp']").value = String(item.whatsapp || "");
    orgMemberEditForm.querySelector("select[name='identificacaoGenero']").value = String(
      item.identificacaoGenero || "Prefiro nao informar"
    );
    orgMemberEditForm.querySelector("input[name='note']").value = String(item.note || "");

    if (orgMemberEditLead) {
      orgMemberEditLead.textContent =
        `Editando credencial ${userNumber} (${roleLabelFromValue(item.role)}). Salve para aplicar.`;
    }

    orgMemberEditModal.classList.remove("hidden");
    orgMemberEditModal.hidden = false;
    orgMemberEditModal.setAttribute("aria-hidden", "false");
  }

  function closeMemberEditModal() {
    if (!orgMemberEditModal || !orgMemberEditForm) {
      return;
    }

    orgMemberEditForm.reset();
    orgMemberEditModal.classList.add("hidden");
    orgMemberEditModal.hidden = true;
    orgMemberEditModal.setAttribute("aria-hidden", "true");
  }

  function rerenderMemberStatusesFromSnapshot() {
    updateAdminDashboardMetrics(memberStatusSnapshot);
    const filtered = getFilteredMemberStatuses(memberStatusSnapshot);
    renderMemberStatuses(filtered);
  }

  function renderMemberStatuses(items) {
    if (!orgMembersList) {
      return;
    }

    orgMembersList.innerHTML = "";
    if (!Array.isArray(items) || items.length === 0) {
      const empty = document.createElement("p");
      empty.className = "org-owner-empty";
      empty.textContent = "Nenhum membro ativo encontrado.";
      orgMembersList.appendChild(empty);
      return;
    }

    const groupedByRole = new Map();
    items.forEach((item) => {
      const role = normalizeRoleValue(item.role);
      if (!groupedByRole.has(role)) {
        groupedByRole.set(role, []);
      }
      groupedByRole.get(role).push(item);
    });

    const orderedRoles = sortedRoleKeysFromMap(groupedByRole);
    orderedRoles.forEach((role) => {
      const list = groupedByRole.get(role) || [];
      const { block, list: roleList } = createRoleGroupBlock(role, list.length, "membro");

      list.forEach((item) => {
        const wrapper = document.createElement("article");
        wrapper.className = "org-owner-item";

        const info = document.createElement("div");
        info.className = "org-owner-request-info";

        const statusText = item.emailVerifiedAt
          ? `Verificado em ${new Date(item.emailVerifiedAt).toLocaleString("pt-BR")}`
          : "Pendente de verificação";

        const fields = [
          ["Credencial", item.credentialNumber || item.userNumber || "-"],
          ["Nome", item.fullName || "-"],
          ["Cargo", roleLabelFromValue(item.role)],
          ["E-mail", item.email || "-"],
          ["Nome no jogo", item.inGameName || "-"],
          ["ID no jogo", item.gameId || "-"],
          ["ID do servidor", item.serverId || "-"],
          ["WhatsApp", item.whatsapp || "-"],
          ["Identificação", identificationLabelFromValue(item.identificacaoGenero)],
          ["Status do membro", item.status || "active"],
          ["Troca de senha pendente", item.mustChangePassword ? "Sim" : "Não"],
          ["Senha provisória atual", item.temporaryPassword || "-"],
          ["Senha provisória atualizada em", formatDateTime(item.temporaryPasswordUpdatedAt)],
          ["Status e-mail", statusText],
          ["Observacao", item.note || "-"]
        ];

        fields.forEach(([label, value]) => {
          const line = document.createElement("p");
          const labelNode = document.createElement("strong");
          labelNode.textContent = `${label}: `;
          line.appendChild(labelNode);
          line.appendChild(document.createTextNode(String(value)));
          info.appendChild(line);
        });

        wrapper.appendChild(info);
        const actorRole = String(currentSession?.role || "");
        const actorUserNumber = String(currentSession?.userNumber || "");
        const memberUserNumber = String(item.userNumber || "");
        const actorAssignableRoles = new Set(assignableRolesForRole(actorRole));
        const canManageMemberRole =
          isApprovalRole(actorRole) &&
          actorUserNumber !== memberUserNumber &&
          actorAssignableRoles.has(String(item.role || ""));
        const canSendReminder = isApprovalRole(actorRole) && !item.emailVerifiedAt;
        const canEditProfile = canEditMemberProfile(item);

        if (canManageMemberRole || canSendReminder || canEditProfile) {
          const actions = document.createElement("div");
          actions.className = "org-owner-actions";

          if (canSendReminder) {
            const remindBtn = document.createElement("button");
            remindBtn.className = "btn btn-secondary";
            remindBtn.type = "button";
            remindBtn.dataset.memberUserNumber = memberUserNumber;
            remindBtn.dataset.memberAction = "remind-email";
            remindBtn.textContent = "Avisar verificação";
            actions.appendChild(remindBtn);
          }

          if (canManageMemberRole) {
            const roleBtn = document.createElement("button");
            roleBtn.className = "btn btn-secondary";
            roleBtn.type = "button";
            roleBtn.dataset.memberUserNumber = memberUserNumber;
            roleBtn.dataset.memberAction = "change-role";
            roleBtn.dataset.memberRole = String(item.role || "");
            roleBtn.textContent = "Atualizar cargo";
            actions.appendChild(roleBtn);

            const removeBtn = document.createElement("button");
            removeBtn.className = "btn btn-secondary";
            removeBtn.type = "button";
            removeBtn.dataset.memberUserNumber = memberUserNumber;
            removeBtn.dataset.memberAction = "remove-member";
            removeBtn.dataset.memberRole = String(item.role || "");
            removeBtn.textContent = "Remover membro";
            actions.appendChild(removeBtn);
          }

          if (canEditProfile) {
            const editBtn = document.createElement("button");
            editBtn.className = "btn btn-secondary";
            editBtn.type = "button";
            editBtn.dataset.memberUserNumber = memberUserNumber;
            editBtn.dataset.memberAction = "edit-profile";
            editBtn.textContent = "Atualizar cadastro";
            actions.appendChild(editBtn);
          }

          wrapper.appendChild(actions);
        }

        roleList.appendChild(wrapper);
      });

      orgMembersList.appendChild(block);
    });
  }

  function formatDateTime(value) {
    if (!value) {
      return "-";
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return String(value);
    }

    return parsed.toLocaleString("pt-BR");
  }

  function isPerformanceEditorRole(role) {
    return performanceEditorRoles.has(String(role || "").trim());
  }

  function clampPerformanceValue(value) {
    const num = Number(value);
    if (!Number.isFinite(num)) {
      return 0;
    }
    return Math.min(10, Math.max(0, num));
  }

  function normalizePercentValue(value) {
    const num = Number(value);
    if (!Number.isFinite(num)) {
      return 0;
    }
    return Math.min(100, Math.max(0, num));
  }

  function formatPercentValue(value) {
    const num = Number(value);
    if (!Number.isFinite(num)) {
      return "0%";
    }
    const rounded = Math.round(num * 10) / 10;
    if (Math.abs(rounded - Math.round(rounded)) < 0.01) {
      return `${Math.round(rounded).toLocaleString("pt-BR")}%`;
    }
    return `${rounded.toLocaleString("pt-BR", {
      minimumFractionDigits: 1,
      maximumFractionDigits: 1
    })}%`;
  }

  function formatSignedPercentDelta(value) {
    const num = Number(value);
    if (!Number.isFinite(num)) {
      return "0%";
    }
    const sign = num > 0 ? "+" : "";
    return `${sign}${formatPercentValue(num)}`;
  }

  function getPerformanceTier(percent) {
    const value = normalizePercentValue(percent);
    if (value >= 85) {
      return {
        label: "Elite competitiva",
        className: "is-elite"
      };
    }
    if (value >= 70) {
      return {
        label: "Alto rendimento",
        className: "is-competitive"
      };
    }
    if (value >= 50) {
      return {
        label: "Em evolução",
        className: "is-attention"
      };
    }
    return {
      label: "Ajuste crítico",
      className: "is-critical"
    };
  }

  function performanceRoleLabel(role) {
    return roleLabelFromValue(role || "sem_cargo");
  }

  function getPerformanceCategoryLabel(key) {
    const found = performanceCategories.find((item) => item.key === key);
    return found ? found.label : key;
  }

  function parsePerformanceBullets(textValue) {
    return String(textValue || "")
      .split(/\r?\n/g)
      .map((line) => line.trim())
      .filter(Boolean)
      .slice(0, 12);
  }

  function clearPerformanceReconnectTimer() {
    if (!performanceEventReconnectTimer) {
      return;
    }
    window.clearTimeout(performanceEventReconnectTimer);
    performanceEventReconnectTimer = null;
  }

  function clearPerformanceReloadTimer() {
    if (!performanceReloadTimer) {
      return;
    }
    window.clearTimeout(performanceReloadTimer);
    performanceReloadTimer = null;
  }

  function closePerformanceEventSource() {
    clearPerformanceReconnectTimer();
    clearPerformanceReloadTimer();
    if (!performanceEventSource) {
      return;
    }
    try {
      performanceEventSource.close();
    } catch (_error) {
      // noop
    }
    performanceEventSource = null;
  }

  function schedulePerformanceReload() {
    clearPerformanceReloadTimer();
    performanceReloadTimer = window.setTimeout(() => {
      performanceReloadTimer = null;
      void refreshPerformanceBoard(true);
    }, 260);
  }

  function setPerformanceHint(message) {
    if (!orgPerformanceHint) {
      return;
    }
    orgPerformanceHint.textContent = message || "";
  }

  function setPerformanceShellVisibility(visible) {
    if (!orgPerformanceShell) {
      return;
    }
    orgPerformanceShell.classList.toggle("hidden", !visible);
    orgPerformanceShell.hidden = !visible;
  }

  function setPerformanceEditorVisibility(visible) {
    if (!orgPerformanceEditor) {
      return;
    }
    orgPerformanceEditor.classList.toggle("hidden", !visible);
    orgPerformanceEditor.hidden = !visible;
  }

  function setPerformancePickerVisibility(visible) {
    if (!orgPerformancePicker) {
      return;
    }
    orgPerformancePicker.classList.toggle("hidden", !visible);
    orgPerformancePicker.hidden = !visible;
  }

  function setPerformanceTitle(title) {
    if (!orgPerformanceTitle) {
      return;
    }
    orgPerformanceTitle.textContent = title;
  }

  function setPerformanceSummaryLoadingState(message) {
    if (!orgPerformanceSummary) {
      return;
    }
    orgPerformanceSummary.innerHTML = "";
    const loading = document.createElement("p");
    loading.className = "org-owner-empty";
    loading.textContent = message;
    orgPerformanceSummary.appendChild(loading);
  }

  function setPerformanceWeeklyInfo(message, tone = "") {
    if (!orgPerformanceWeekly) {
      return;
    }
    orgPerformanceWeekly.innerHTML = "";
    const text = document.createElement("p");
    text.className = "org-owner-empty";
    if (tone) {
      text.style.color = tone;
    }
    text.textContent = message;
    orgPerformanceWeekly.appendChild(text);
  }

  function buildPerformanceScoreInputs() {
    if (!orgPerformanceScores) {
      return;
    }
    if (orgPerformanceScores.childElementCount > 0) {
      return;
    }

    const fragment = document.createDocumentFragment();
    performanceCategories.forEach((category) => {
      const row = document.createElement("div");
      row.className = "perf-score-row";

      const label = document.createElement("label");
      label.className = "perf-score-label";
      label.textContent = category.label;
      label.htmlFor = `perf-score-${category.key}`;

      const input = document.createElement("input");
      input.type = "range";
      input.min = "0";
      input.max = "10";
      input.step = "0.1";
      input.value = "7.5";
      input.required = true;
      input.dataset.scoreKey = category.key;
      input.name = `scores.${category.key}`;
      input.id = `perf-score-${category.key}`;

      const value = document.createElement("span");
      value.className = "perf-score-value";
      value.textContent = "7,5 / 10";

      const syncValue = () => {
        const clamped = clampPerformanceValue(input.value);
        value.textContent = `${clamped.toLocaleString("pt-BR", {
          minimumFractionDigits: 1,
          maximumFractionDigits: 1
        })} / 10`;
      };
      input.addEventListener("input", syncValue);
      syncValue();

      row.appendChild(label);
      row.appendChild(input);
      row.appendChild(value);
      fragment.appendChild(row);
    });

    orgPerformanceScores.appendChild(fragment);
  }

  function getPerformanceScoreInputs() {
    if (!orgPerformanceScores) {
      return [];
    }
    return Array.from(orgPerformanceScores.querySelectorAll("input[data-score-key]"));
  }

  function setPerformanceFormScores(scores = null) {
    getPerformanceScoreInputs().forEach((input) => {
      const key = String(input.dataset.scoreKey || "");
      const rawValue = scores && Object.prototype.hasOwnProperty.call(scores, key) ? scores[key] : 7.5;
      const clamped = clampPerformanceValue(rawValue);
      input.value = clamped.toString();
      input.dispatchEvent(new Event("input", { bubbles: false }));
    });
  }

  function readPerformanceFormScores() {
    const result = {};
    getPerformanceScoreInputs().forEach((input) => {
      const key = String(input.dataset.scoreKey || "");
      if (!key) {
        return;
      }
      result[key] = clampPerformanceValue(input.value);
    });
    return result;
  }

  function getPlayerLabel(player) {
    const parts = [];
    const fullName = String(player?.fullName || "").trim();
    const inGameName = String(player?.inGameName || "").trim();
    const userNumber = String(player?.userNumber || "").trim();
    if (fullName) {
      parts.push(fullName);
    }
    if (inGameName) {
      parts.push(`@${inGameName}`);
    }
    if (userNumber) {
      parts.push(`#${userNumber}`);
    }
    return parts.join(" • ") || "Player";
  }

  function createNoDataLine(message) {
    const empty = document.createElement("p");
    empty.className = "org-owner-empty";
    empty.textContent = message;
    return empty;
  }

  function renderPerformanceSummary(player, summary, includeNotes) {
    if (!orgPerformanceSummary) {
      return;
    }

    orgPerformanceSummary.innerHTML = "";
    if (!summary) {
      orgPerformanceSummary.appendChild(createNoDataLine("Sem dados de desempenho para este jogador."));
      return;
    }

    const overallPercent = normalizePercentValue(summary.overallPercent || 0);
    const currentWeekPercent =
      summary.currentWeekPercent === null || summary.currentWeekPercent === undefined
        ? null
        : normalizePercentValue(summary.currentWeekPercent);
    const contributorsCount = Array.isArray(summary.contributors) ? summary.contributors.length : 0;
    const deltaPercent = currentWeekPercent === null ? null : Math.round((currentWeekPercent - overallPercent) * 10) / 10;
    const tier = getPerformanceTier(overallPercent);
    const circumference = 2 * Math.PI * 50;
    const dashOffset = circumference - (overallPercent / 100) * circumference;

    const overview = document.createElement("div");
    overview.className = "perf-overview";

    const gauge = document.createElement("div");
    gauge.className = "perf-gauge";
    gauge.innerHTML = `
      <svg class="perf-gauge-svg" viewBox="0 0 120 120" aria-hidden="true">
        <circle class="perf-gauge-bg" cx="60" cy="60" r="50" stroke-width="10" fill="none"></circle>
        <circle
          class="perf-gauge-progress"
          cx="60"
          cy="60"
          r="50"
          stroke-width="10"
          fill="none"
          stroke-dasharray="${circumference.toFixed(2)}"
          stroke-dashoffset="${dashOffset.toFixed(2)}"
          stroke-linecap="round"
        ></circle>
      </svg>
    `;

    const gaugeMeta = document.createElement("div");
    gaugeMeta.className = "perf-gauge-meta";
    const gaugeValue = document.createElement("p");
    gaugeValue.className = "perf-gauge-value";
    gaugeValue.textContent = formatPercentValue(overallPercent);
    const gaugeLabel = document.createElement("p");
    gaugeLabel.className = "perf-gauge-label";
    gaugeLabel.textContent = tier.label;
    const gaugeSub = document.createElement("p");
    gaugeSub.className = "perf-gauge-sub";
    gaugeSub.textContent = `Semana foco ${summary.week || "-"}`;
    gaugeMeta.appendChild(gaugeValue);
    gaugeMeta.appendChild(gaugeLabel);
    gaugeMeta.appendChild(gaugeSub);
    gauge.appendChild(gaugeMeta);
    overview.appendChild(gauge);

    const kpis = document.createElement("div");
    kpis.className = "perf-kpis";

    const kpiRows = [
      ["Jogador", getPlayerLabel(player)],
      ["Foco semanal", currentWeekPercent === null ? "Sem notas" : formatPercentValue(currentWeekPercent)],
      ["Variação da semana", deltaPercent === null ? "Sem base" : formatSignedPercentDelta(deltaPercent)],
      ["Última atualização", formatDateTime(summary.lastUpdatedAt)]
    ];
    kpiRows.forEach(([key, value]) => {
      const box = document.createElement("article");
      box.className = "perf-kpi";
      const title = document.createElement("p");
      title.className = "perf-kpi-key";
      title.textContent = key;
      const val = document.createElement("p");
      val.className = "perf-kpi-val";
      val.textContent = value;
      box.appendChild(title);
      box.appendChild(val);
      kpis.appendChild(box);
    });

    overview.appendChild(kpis);
    orgPerformanceSummary.appendChild(overview);

    const statusStrip = document.createElement("div");
    statusStrip.className = "perf-status-strip";
    const statusChip = document.createElement("span");
    statusChip.className = `perf-status-chip ${tier.className}`;
    statusChip.textContent = tier.label;
    statusStrip.appendChild(statusChip);
    if (deltaPercent !== null) {
      const deltaChip = document.createElement("span");
      deltaChip.className = `perf-delta-chip ${deltaPercent >= 0 ? "is-positive" : "is-negative"}`;
      deltaChip.textContent = `Semana ${formatSignedPercentDelta(deltaPercent)}`;
      statusStrip.appendChild(deltaChip);
    }
    const contribChip = document.createElement("span");
    contribChip.className = "perf-delta-chip";
    contribChip.textContent = `Avaliadores ativos: ${contributorsCount}`;
    statusStrip.appendChild(contribChip);
    orgPerformanceSummary.appendChild(statusStrip);

    const barsTitle = document.createElement("p");
    barsTitle.className = "perf-section-title";
    barsTitle.textContent = "Médias por categoria";
    orgPerformanceSummary.appendChild(barsTitle);

    const bars = document.createElement("div");
    bars.className = "perf-bars";
    performanceCategories.forEach((category) => {
      const allTimeValue = clampPerformanceValue(summary?.categories?.allTime?.[category.key] ?? 0);
      const currentValueRaw = summary?.categories?.currentWeek?.[category.key];
      const currentValue =
        currentValueRaw === null || currentValueRaw === undefined
          ? null
          : clampPerformanceValue(currentValueRaw);
      const percent = Math.round((allTimeValue / 10) * 1000) / 10;

      const row = document.createElement("article");
      row.className = "perf-bar";
      const head = document.createElement("div");
      head.className = "perf-bar-head";
      const label = document.createElement("span");
      label.className = "perf-bar-label";
      label.textContent = getPerformanceCategoryLabel(category.key);
      const value = document.createElement("span");
      value.className = "perf-bar-val";
      value.textContent =
        currentValue === null
          ? `${allTimeValue.toLocaleString("pt-BR", { minimumFractionDigits: 1, maximumFractionDigits: 1 })} / 10`
          : `${allTimeValue.toLocaleString("pt-BR", { minimumFractionDigits: 1, maximumFractionDigits: 1 })} / 10 (semana ${currentValue.toLocaleString("pt-BR", { minimumFractionDigits: 1, maximumFractionDigits: 1 })})`;
      head.appendChild(label);
      head.appendChild(value);

      const track = document.createElement("div");
      track.className = "perf-bar-track";
      const fill = document.createElement("span");
      fill.className = "perf-bar-fill";
      fill.style.width = `${percent}%`;
      track.appendChild(fill);

      row.appendChild(head);
      row.appendChild(track);
      bars.appendChild(row);
    });
    orgPerformanceSummary.appendChild(bars);

    const trendBlock = document.createElement("section");
    trendBlock.className = "perf-trend";
    const trendTitle = document.createElement("p");
    trendTitle.className = "perf-section-title";
    trendTitle.textContent = "Tendência (8 semanas)";
    trendBlock.appendChild(trendTitle);
    const trendBars = document.createElement("div");
    trendBars.className = "perf-trend-bars";
    const trend = Array.isArray(summary.trend) ? summary.trend : [];
    if (trend.length === 0) {
      trendBars.appendChild(createNoDataLine("Sem histórico semanal para exibir."));
    } else {
      trend.forEach((point) => {
        const percent = normalizePercentValue(point?.percent || 0);
        const bar = document.createElement("span");
        bar.className = "perf-trend-bar";
        bar.style.setProperty("--h", `${percent}%`);
        bar.title = `${point.week || "-"} • ${formatPercentValue(percent)}`;
        trendBars.appendChild(bar);
      });
    }
    trendBlock.appendChild(trendBars);
    if (trend.length > 0) {
      const trendLabels = document.createElement("div");
      trendLabels.className = "perf-trend-labels";
      trendLabels.style.gridTemplateColumns = `repeat(${trend.length}, minmax(0, 1fr))`;
      trend.forEach((point) => {
        const label = document.createElement("span");
        label.textContent = String(point.week || "").slice(5) || "--";
        trendLabels.appendChild(label);
      });
      trendBlock.appendChild(trendLabels);
    }
    orgPerformanceSummary.appendChild(trendBlock);

    if (includeNotes && contributorsCount > 0) {
      const contributorsSection = document.createElement("section");
      contributorsSection.className = "perf-contrib";
      const contributorsTitle = document.createElement("p");
      contributorsTitle.className = "perf-section-title";
      contributorsTitle.textContent = "Consolidação da liderança";
      contributorsSection.appendChild(contributorsTitle);
      const contributorRows = document.createElement("div");
      contributorRows.className = "perf-contrib-rows";

      summary.contributors.slice(0, 6).forEach((contributor) => {
        const row = document.createElement("article");
        row.className = "perf-contrib-row";
        const left = document.createElement("span");
        left.textContent = `${performanceRoleLabel(contributor.evaluatorRole)} #${contributor.evaluatorUserNumber || "-"}`;
        const center = document.createElement("span");
        center.textContent = formatPercentValue(contributor.percent || 0);
        const right = document.createElement("span");
        right.textContent = formatDateTime(contributor.updatedAt);
        row.appendChild(left);
        row.appendChild(center);
        row.appendChild(right);
        contributorRows.appendChild(row);
      });

      contributorsSection.appendChild(contributorRows);
      orgPerformanceSummary.appendChild(contributorsSection);
    }

    if (includeNotes) {
      const notes = document.createElement("section");
      notes.className = "perf-notes";

      const strengthsCol = document.createElement("article");
      strengthsCol.className = "perf-notes-col";
      const strengthsTitle = document.createElement("h4");
      strengthsTitle.textContent = "Pontos fortes";
      const strengthsList = document.createElement("ul");
      const strengths = Array.isArray(summary.strengths) ? summary.strengths : [];
      if (strengths.length === 0) {
        const empty = document.createElement("li");
        empty.textContent = "Sem observações nesta semana.";
        strengthsList.appendChild(empty);
      } else {
        strengths.forEach((item) => {
          const li = document.createElement("li");
          li.textContent = item;
          strengthsList.appendChild(li);
        });
      }
      strengthsCol.appendChild(strengthsTitle);
      strengthsCol.appendChild(strengthsList);

      const improvementsCol = document.createElement("article");
      improvementsCol.className = "perf-notes-col";
      const improvementsTitle = document.createElement("h4");
      improvementsTitle.textContent = "A melhorar";
      const improvementsList = document.createElement("ul");
      const improvements = Array.isArray(summary.improvements) ? summary.improvements : [];
      if (improvements.length === 0) {
        const empty = document.createElement("li");
        empty.textContent = "Sem pontos críticos nesta semana.";
        improvementsList.appendChild(empty);
      } else {
        improvements.forEach((item) => {
          const li = document.createElement("li");
          li.textContent = item;
          improvementsList.appendChild(li);
        });
      }
      improvementsCol.appendChild(improvementsTitle);
      improvementsCol.appendChild(improvementsList);

      notes.appendChild(strengthsCol);
      notes.appendChild(improvementsCol);
      orgPerformanceSummary.appendChild(notes);
    }
  }

  function renderPerformanceWeeklyInfo(detail, canEdit) {
    if (!orgPerformanceWeekly) {
      return;
    }
    orgPerformanceWeekly.innerHTML = "";

    if (!canEdit) {
      const text = document.createElement("p");
      text.className = "org-owner-empty";
      text.textContent = "Modo visualização: apenas gráfico e evolução do seu desempenho.";
      orgPerformanceWeekly.appendChild(text);
      return;
    }

    const summary = detail?.summary || null;
    const week = summary?.week || performanceCurrentWeek || "-";

    const meta = document.createElement("article");
    meta.className = "org-owner-item";
    const metaInfo = document.createElement("div");
    metaInfo.className = "org-owner-request-info";
    const contributors = Array.isArray(summary?.contributors) ? summary.contributors : [];
    const lines = [
      ["Semana em foco", week],
      ["Avaliadores na semana", String(contributors.length)],
      ["Média da semana", summary?.currentWeekPercent == null ? "Sem notas" : formatPercentValue(summary.currentWeekPercent)],
      ["Última atualização", formatDateTime(summary?.lastUpdatedAt)]
    ];
    lines.forEach(([label, value]) => {
      const line = document.createElement("p");
      const key = document.createElement("strong");
      key.textContent = `${label}: `;
      line.appendChild(key);
      line.appendChild(document.createTextNode(value));
      metaInfo.appendChild(line);
    });
    meta.appendChild(metaInfo);
    orgPerformanceWeekly.appendChild(meta);

    const updates = Array.isArray(detail?.updates) ? detail.updates : [];
    if (updates.length === 0) {
      orgPerformanceWeekly.appendChild(createNoDataLine("Nenhuma atualização semanal registrada para este player."));
      return;
    }

    const latest = updates.slice(0, 6);
    latest.forEach((update) => {
      const card = document.createElement("article");
      card.className = "org-owner-item";
      const info = document.createElement("div");
      info.className = "org-owner-request-info";
      const fields = [
        ["Semana", update.week || "-"],
        ["Avaliador", `${performanceRoleLabel(update.evaluatorRole)} #${update.evaluatorUserNumber || "-"}`],
        ["Nota geral", formatPercentValue(update.percent || 0)],
        ["Atualizado em", formatDateTime(update.updatedAt)],
        ["Observação", update.note || "-"]
      ];
      fields.forEach(([label, value]) => {
        const line = document.createElement("p");
        const key = document.createElement("strong");
        key.textContent = `${label}: `;
        line.appendChild(key);
        line.appendChild(document.createTextNode(value));
        info.appendChild(line);
      });
      card.appendChild(info);
      orgPerformanceWeekly.appendChild(card);
    });
  }

  function buildPerformanceRankingRows(boardData) {
    const players = Array.isArray(boardData?.players) ? boardData.players : [];
    const summaries = Array.isArray(boardData?.summaries) ? boardData.summaries : [];
    const summaryMap = new Map();
    summaries.forEach((item) => {
      const key = String(item?.playerUserNumber || "").trim();
      if (!key) {
        return;
      }
      summaryMap.set(key, item);
    });

    const rows = players.map((player) => {
      const userNumber = String(player?.userNumber || "").trim();
      const summary = summaryMap.get(userNumber) || {};
      const weekPercentRaw = summary.currentWeekPercent;
      const weekPercent =
        weekPercentRaw === null || weekPercentRaw === undefined
          ? null
          : normalizePercentValue(weekPercentRaw);
      const overallPercent = normalizePercentValue(summary.overallPercent || 0);
      const rankScore = weekPercent === null ? overallPercent : weekPercent;

      return {
        userNumber,
        fullName: String(player?.fullName || "").trim(),
        inGameName: String(player?.inGameName || "").trim(),
        weekPercent,
        overallPercent,
        rankScore
      };
    });

    rows.sort((a, b) => {
      const scoreDiff = b.rankScore - a.rankScore;
      if (Math.abs(scoreDiff) > 0.0001) {
        return scoreDiff;
      }
      const overallDiff = b.overallPercent - a.overallPercent;
      if (Math.abs(overallDiff) > 0.0001) {
        return overallDiff;
      }
      return String(a.userNumber).localeCompare(String(b.userNumber), "pt-BR");
    });

    rows.forEach((row, index) => {
      row.position = index + 1;
    });
    return rows;
  }

  function renderPerformanceRanking(boardData) {
    if (!orgPerformanceRanking) {
      return;
    }

    orgPerformanceRanking.innerHTML = "";
    if (!currentSession) {
      orgPerformanceRanking.appendChild(createNoDataLine("Faça login para visualizar o ranking."));
      return;
    }

    const role = String(currentSession.role || "");
    if (role === "player") {
      const ranking = boardData?.playerRanking || null;
      const box = document.createElement("div");
      box.className = "perf-ranking-meta";
      const line = document.createElement("p");
      if (!ranking || !ranking.position || !ranking.totalPlayers) {
        line.textContent = "Seu ranking semanal será exibido após as primeiras avaliações.";
      } else {
        const weekPercent =
          ranking.currentWeekPercent === null || ranking.currentWeekPercent === undefined
            ? "Sem nota semanal"
            : formatPercentValue(ranking.currentWeekPercent);
        line.textContent =
          `Posição atual: ${ranking.position}º de ${ranking.totalPlayers} players. ` +
          `Semana: ${weekPercent}. Média geral: ${formatPercentValue(ranking.overallPercent || 0)}.`;
      }
      box.appendChild(line);
      orgPerformanceRanking.appendChild(box);
      return;
    }

    const rows = buildPerformanceRankingRows(boardData);
    if (rows.length === 0) {
      orgPerformanceRanking.appendChild(createNoDataLine("Sem players ativos para gerar ranking."));
      return;
    }

    const top = rows.slice(0, 5);
    const topBlock = document.createElement("div");
    topBlock.className = "perf-ranking-top";
    top.forEach((row) => {
      const line = document.createElement("article");
      const isSelected = String(row.userNumber) === String(performanceSelectedPlayer || "");
      line.className = `perf-ranking-row${isSelected ? " is-selected" : ""}`;

      const pos = document.createElement("span");
      pos.className = "perf-ranking-pos";
      pos.textContent = `#${row.position}`;

      const player = document.createElement("span");
      player.className = "perf-ranking-player";
      const identity = row.fullName || row.inGameName || `Player ${row.userNumber}`;
      const alias = row.inGameName ? ` (@${row.inGameName})` : "";
      player.textContent = `${identity}${alias}`;

      const week = document.createElement("span");
      week.className = "perf-ranking-week";
      week.textContent = `Semana ${row.weekPercent === null ? "-" : formatPercentValue(row.weekPercent)}`;

      const overall = document.createElement("span");
      overall.className = "perf-ranking-overall";
      overall.textContent = `Geral ${formatPercentValue(row.overallPercent)}`;

      line.appendChild(pos);
      line.appendChild(player);
      line.appendChild(week);
      line.appendChild(overall);
      topBlock.appendChild(line);
    });
    orgPerformanceRanking.appendChild(topBlock);

    const selected = rows.find((item) => String(item.userNumber) === String(performanceSelectedPlayer || ""));
    if (selected && selected.position > 5) {
      const meta = document.createElement("div");
      meta.className = "perf-ranking-meta";
      const text = document.createElement("p");
      text.textContent =
        `Jogador selecionado está na posição ${selected.position} de ${rows.length}. ` +
        `Semana: ${selected.weekPercent === null ? "-" : formatPercentValue(selected.weekPercent)}. ` +
        `Geral: ${formatPercentValue(selected.overallPercent)}.`;
      meta.appendChild(text);
      orgPerformanceRanking.appendChild(meta);
    }
  }

  function populatePerformancePlayerSelect(players) {
    if (!orgPerformancePlayerSelect) {
      return;
    }

    orgPerformancePlayerSelect.innerHTML = "";
    const list = Array.isArray(players) ? players : [];
    if (list.length === 0) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "Sem players ativos";
      orgPerformancePlayerSelect.appendChild(option);
      orgPerformancePlayerSelect.disabled = true;
      return;
    }

    orgPerformancePlayerSelect.disabled = false;
    list.forEach((player) => {
      const option = document.createElement("option");
      option.value = String(player.userNumber || "");
      option.textContent = getPlayerLabel(player);
      orgPerformancePlayerSelect.appendChild(option);
    });

    if (performanceSelectedPlayer && list.some((player) => String(player.userNumber) === performanceSelectedPlayer)) {
      orgPerformancePlayerSelect.value = performanceSelectedPlayer;
      return;
    }

    orgPerformancePlayerSelect.value = String(list[0].userNumber || "");
    performanceSelectedPlayer = orgPerformancePlayerSelect.value;
  }

  function applyPerformanceEditorWeek(detail) {
    if (!orgPerformanceForm) {
      return;
    }

    const weekInput = orgPerformanceForm.querySelector("input[name='week']");
    const strengthsInput = orgPerformanceForm.querySelector("textarea[name='strengths']");
    const improvementsInput = orgPerformanceForm.querySelector("textarea[name='improvements']");
    const noteInput = orgPerformanceForm.querySelector("textarea[name='note']");
    const myWeekData = detail?.myUpdateThisWeek || null;
    const defaultWeek = detail?.week || performanceCurrentWeek || "";

    if (weekInput) {
      weekInput.value = myWeekData?.week || defaultWeek;
    }

    if (myWeekData) {
      setPerformanceFormScores(myWeekData.scores || {});
      if (strengthsInput) {
        strengthsInput.value = Array.isArray(myWeekData.strengths) ? myWeekData.strengths.join("\n") : "";
      }
      if (improvementsInput) {
        improvementsInput.value = Array.isArray(myWeekData.improvements)
          ? myWeekData.improvements.join("\n")
          : "";
      }
      if (noteInput) {
        noteInput.value = myWeekData.note || "";
      }
      return;
    }

    setPerformanceFormScores();
    if (strengthsInput) {
      strengthsInput.value = "";
    }
    if (improvementsInput) {
      improvementsInput.value = "";
    }
    if (noteInput) {
      noteInput.value = "";
    }
  }

  async function loadPerformancePlayer(playerUserNumber, silent = false) {
    if (!currentSession || !orgPerformanceShell || !playerUserNumber) {
      return;
    }

    const isPlayer = String(currentSession.role || "") === "player";
    const canEdit = isPerformanceEditorRole(currentSession.role);
    const targetUserNumber = String(playerUserNumber || "").trim();
    if (!/^[0-9]{4,12}$/.test(targetUserNumber)) {
      setPerformanceHint("Credencial de player inválida para carregar desempenho.");
      return;
    }

    if (!silent) {
      setPerformanceSummaryLoadingState("Carregando dados do jogador...");
    }

    const { response, body } = await secureOrgRequest(
      `/api/org/performance/player/${encodeURIComponent(targetUserNumber)}`,
      { method: "GET" }
    );

    if (!response.ok || !body?.ok) {
      setPerformanceHint(body?.error || "Falha ao carregar desempenho do jogador.");
      if (!silent) {
        setPerformanceSummaryLoadingState("Não foi possível carregar os dados deste jogador.");
      }
      return;
    }

    performanceSelectedPlayer = String(body?.player?.userNumber || targetUserNumber);
    performanceCurrentWeek = String(body?.week || body?.summary?.week || performanceCurrentWeek || "");
    if (orgPerformancePlayerSelect && !orgPerformancePlayerSelect.disabled) {
      orgPerformancePlayerSelect.value = performanceSelectedPlayer;
    }

    if (orgPerformancePlayerInput) {
      orgPerformancePlayerInput.value = performanceSelectedPlayer;
    }

    const playerLabel = getPlayerLabel(body.player || {});
    setPerformanceTitle(isPlayer ? "Seu desempenho" : `Painel do jogador: ${playerLabel}`);
    renderPerformanceSummary(body.player, body.summary, !isPlayer);
    renderPerformanceWeeklyInfo(body, canEdit && !isPlayer);
    renderPerformanceRanking(performanceBoardSnapshot);

    if (!isPlayer && canEdit && orgPerformanceForm) {
      applyPerformanceEditorWeek(body);
      if (orgPerformanceHint) {
        const hasMyUpdate = Boolean(body?.myUpdateThisWeek);
        setPerformanceHint(
          hasMyUpdate
            ? "Você já possui atualização na semana atual. Edite e salve para substituir."
            : "Preencha a avaliação semanal do jogador selecionado."
        );
      }
    } else if (isPlayer) {
      setPerformanceHint("Visualização somente leitura: a liderança atualiza este quadro semanalmente.");
    } else {
      setPerformanceHint("Seu cargo não possui permissão para editar a planilha de desempenho.");
    }
  }

  async function refreshPerformanceBoard(silent = false) {
    if (!currentSession || !orgPerformanceShell) {
      return;
    }

    const isPlayer = String(currentSession.role || "") === "player";
    const canEdit = isPerformanceEditorRole(currentSession.role);

    setPerformanceShellVisibility(true);
    setPerformanceEditorVisibility(!isPlayer && canEdit);
    setPerformancePickerVisibility(!isPlayer);

    if (!silent) {
      setPerformanceSummaryLoadingState("Carregando planilha de desempenho...");
    }

    const { response, body } = await secureOrgRequest("/api/org/performance/board", {
      method: "GET"
    });

    if (!response.ok || !body?.ok) {
      setPerformanceHint(body?.error || "Falha ao carregar planilha de desempenho.");
      if (!silent) {
        setPerformanceSummaryLoadingState("Não foi possível carregar a planilha.");
      }
      return;
    }

    performanceBoardMode = String(body.mode || "");
    performanceCurrentWeek = String(body.week || "");
    performanceBoardSnapshot = body;

    if (performanceBoardMode === "player" || isPlayer) {
      performanceSelectedPlayer = String(body?.player?.userNumber || currentSession.userNumber || "");
      setPerformancePickerVisibility(false);
      setPerformanceEditorVisibility(false);
      setPerformanceTitle("Seu desempenho");
      if (orgPerformancePlayerInput) {
        orgPerformancePlayerInput.value = performanceSelectedPlayer;
      }
      renderPerformanceSummary(body.player || {}, body.summary || null, false);
      renderPerformanceWeeklyInfo({ summary: body.summary || null }, false);
      renderPerformanceRanking(body);
      setPerformanceHint("Seu painel mostra a média consolidada em tempo real.");
      return;
    }

    const players = Array.isArray(body.players) ? body.players : [];
    populatePerformancePlayerSelect(players);
    if (!performanceSelectedPlayer && players.length > 0) {
      performanceSelectedPlayer = String(players[0].userNumber || "");
    }
    if (orgPerformancePlayerInput) {
      orgPerformancePlayerInput.value = performanceSelectedPlayer || "";
    }

    if (!performanceSelectedPlayer) {
      setPerformanceTitle("Painel de desempenho");
      renderPerformanceSummary({}, null, true);
      setPerformanceWeeklyInfo("Cadastre pelo menos um player ativo para iniciar a planilha.");
      renderPerformanceRanking(body);
      setPerformanceEditorVisibility(false);
      setPerformanceHint("Sem players ativos no momento.");
      return;
    }

    await loadPerformancePlayer(performanceSelectedPlayer, true);
  }

  function initPerformanceEvents() {
    if (!window.EventSource || !currentSession || !orgPerformanceShell) {
      return;
    }

    closePerformanceEventSource();
    const source = new EventSource("/api/org/performance/events", { withCredentials: true });
    performanceEventSource = source;

    source.addEventListener("performance_ready", () => {
      clearPerformanceReconnectTimer();
    });

    source.addEventListener("performance_update", (event) => {
      let payload = null;
      try {
        payload = JSON.parse(event.data || "{}");
      } catch (_error) {
        return;
      }

      const target = String(payload?.playerUserNumber || "");
      if (!target) {
        return;
      }

      const isPlayer = String(currentSession?.role || "") === "player";
      if (isPlayer && target !== String(currentSession?.userNumber || "")) {
        return;
      }

      if (!isPlayer && performanceSelectedPlayer && target !== performanceSelectedPlayer) {
        return;
      }

      schedulePerformanceReload();
    });

    source.onerror = () => {
      if (performanceEventSource !== source) {
        return;
      }

      closePerformanceEventSource();
      if (!currentSession || !orgPerformanceShell) {
        return;
      }

      performanceEventReconnectTimer = window.setTimeout(() => {
        performanceEventReconnectTimer = null;
        initPerformanceEvents();
      }, 2600);
    };
  }

  function renderMemberDataList(target, items, getFields, emptyMessage) {
    if (!target) {
      return;
    }

    target.innerHTML = "";
    if (!Array.isArray(items) || items.length === 0) {
      const empty = document.createElement("p");
      empty.className = "org-owner-empty";
      empty.textContent = emptyMessage;
      target.appendChild(empty);
      return;
    }

    items.forEach((item) => {
      const wrapper = document.createElement("article");
      wrapper.className = "org-owner-item";

      const info = document.createElement("div");
      info.className = "org-owner-request-info";

      const fields = getFields(item) || [];
      fields.forEach(([label, value]) => {
        const line = document.createElement("p");
        const labelNode = document.createElement("strong");
        labelNode.textContent = `${label}: `;
        line.appendChild(labelNode);
        line.appendChild(document.createTextNode(String(value ?? "-")));
        info.appendChild(line);
      });

      wrapper.appendChild(info);
      target.appendChild(wrapper);
    });
  }

  async function refreshMemberDataPanel() {
    if (!currentSession || !orgMemberData) {
      return;
    }

    const { response, body } = await secureOrgRequest("/api/org/panel/full-data", {
      method: "GET"
    });

    if (!response.ok || !body?.ok) {
      setState(body?.error || "Falha ao carregar painel completo da organização.", "#ffb3c0");
      return;
    }

    const canSeeTemporaryPassword = isApprovalRole(currentSession?.role);

    renderMemberDataList(
      orgMemberSelfList,
      body.me ? [body.me] : [],
      (item) => {
        const fields = [
          ["Credencial", item.credentialNumber || item.userNumber || "-"],
          ["Nome", item.fullName || "-"],
          ["Usuario", item.username || "-"],
          ["Cargo", roleLabelFromValue(item.role)],
          ["E-mail", item.email || "-"],
          ["E-mail verificado", item.emailVerifiedAt ? formatDateTime(item.emailVerifiedAt) : "Pendente"],
          ["Nome no jogo", item.inGameName || "-"],
          ["ID no jogo", item.gameId || "-"],
          ["ID do servidor", item.serverId || "-"],
          ["WhatsApp", item.whatsapp || "-"],
          ["Identificação", identificationLabelFromValue(item.identificacaoGenero)],
          ["Observação", item.note || "-"],
          ["Status", item.status || "active"],
          ["Troca de senha pendente", item.mustChangePassword ? "Sim" : "Não"],
          ["Aprovado em", formatDateTime(item.approvedAt)],
          ["Criado em", formatDateTime(item.createdAt)],
          ["Atualizado em", formatDateTime(item.updatedAt)]
        ];
        if (canSeeTemporaryPassword) {
          fields.splice(
            13,
            0,
            ["Senha provisória atual", item.temporaryPassword || "-"],
            ["Senha provisória atualizada em", formatDateTime(item.temporaryPasswordUpdatedAt)]
          );
        }
        return fields;
      },
      "Seu cadastro ainda não foi localizado."
    );

    renderMemberDataList(
      orgMemberUsersList,
      body.users || [],
      (item) => {
        const fields = [
          ["Credencial", item.credentialNumber || item.userNumber || "-"],
          ["Nome", item.fullName || "-"],
          ["Usuario", item.username || "-"],
          ["Cargo", roleLabelFromValue(item.role)],
          ["E-mail", item.email || "-"],
          ["E-mail verificado", item.emailVerifiedAt ? formatDateTime(item.emailVerifiedAt) : "Pendente"],
          ["Nome no jogo", item.inGameName || "-"],
          ["ID no jogo", item.gameId || "-"],
          ["ID do servidor", item.serverId || "-"],
          ["WhatsApp", item.whatsapp || "-"],
          ["Identificação", identificationLabelFromValue(item.identificacaoGenero)],
          ["Observação", item.note || "-"],
          ["Status", item.status || "active"],
          ["Troca de senha pendente", item.mustChangePassword ? "Sim" : "Não"],
          ["Aprovado em", formatDateTime(item.approvedAt)],
          ["Aprovado por", item.approvedBy || "-"],
          ["Criado em", formatDateTime(item.createdAt)],
          ["Atualizado em", formatDateTime(item.updatedAt)]
        ];
        if (canSeeTemporaryPassword) {
          fields.splice(
            13,
            0,
            ["Senha provisória atual", item.temporaryPassword || "-"],
            ["Senha provisória atualizada em", formatDateTime(item.temporaryPasswordUpdatedAt)]
          );
        }
        return fields;
      },
      "Nenhum membro cadastrado."
    );

    renderMemberDataList(
      orgMemberRequestsList,
      body.requests || [],
      (item) => [
        ["Solicitação", item.id || "-"],
        ["Criado em", formatDateTime(item.createdAt)],
        ["Status", item.status || "pending"],
        ["Nome", item.fullName || "-"],
        ["Função desejada", roleLabelFromValue(item.desiredRole)],
        ["Função final", item.finalRole ? roleLabelFromValue(item.finalRole) : "-"],
        ["Credencial gerada", item.userNumber || "-"],
        ["E-mail", item.email || "-"],
        ["E-mail verificado", item.emailVerifiedAt ? formatDateTime(item.emailVerifiedAt) : "Pendente"],
        ["Nome no jogo", item.inGameName || "-"],
        ["ID no jogo", item.gameId || "-"],
        ["ID do servidor", item.serverId || "-"],
        ["Identificação", identificationLabelFromValue(item.identificacaoGenero)],
        ["Observação", item.note || "-"],
        ["Revisado em", formatDateTime(item.reviewedAt)],
        ["Revisado por", item.reviewedBy || "-"],
        ["Motivo", item.decisionReason || "-"]
      ],
      "Nenhuma solicitação de cadastro encontrada."
    );

    renderMemberDataList(
      orgMemberPreregList,
      body.preRegistrations || [],
      (item) => [
        ["Pre-cadastro", item.id || "-"],
        ["Protocolo de envio", item.submissionId || "-"],
        ["Criado em", formatDateTime(item.createdAt)],
        ["Status", item.status || "pending"],
        ["Jogo", item.jogo || "Mobile Legends"],
        ["Nome completo", item.nomeCompleto || "-"],
        ["Nick in-game", item.nickInGame || "-"],
        ["Elo máximo", item.eloMaximo || "-"],
        ["WR nas rankeadas", item.wrRanked ?? "-"],
        ["Máximo de estrelas", item.maximoEstrelas ?? "-"],
        ["Rota principal", item.rotaPrincipal || "-"],
        ["Horario", item.horarioDisponivel || "-"],
        ["Identificação", identificationLabelFromValue(item.identificacaoGenero)],
        ["Discord", item.discord || "-"],
        ["ID do jogo", item.idJogo || "-"],
        ["Server", item.serverJogo || "-"],
        ["WhatsApp", item.whatsapp || "-"],
        ["Enviado em", formatDateTime(item.enviadoEm)]
      ],
      "Nenhum pré-cadastro do formulário encontrado."
    );
  }

  async function refreshOwnerRequests() {
    if (!currentSession || !isApprovalRole(currentSession.role) || !orgOwnerTools) {
      return;
    }

    const { response, body } = await secureOrgRequest("/api/org/admin/requests", {
      method: "GET"
    });

    if (!response.ok || !body?.ok) {
      setState(body?.error || "Falha ao carregar pendencias da org.");
      return;
    }

    renderOwnerRequests(body.items || []);
  }

  async function refreshMemberStatuses() {
    if (!currentSession || !isApprovalRole(currentSession.role)) {
      return;
    }

    const { response, body } = await secureOrgRequest("/api/org/admin/users", {
      method: "GET"
    });

    if (!response.ok || !body?.ok) {
      setState(body?.error || "Falha ao carregar status de verificação de e-mail.");
      return;
    }

    memberStatusSnapshot = Array.isArray(body.items) ? body.items : [];
    rerenderMemberStatusesFromSnapshot();
  }

  function applySession(session) {
    roleClassList.forEach((roleClass) => orgState.classList.remove(roleClass));

    if (!session) {
      closePerformanceEventSource();
      performanceSelectedPlayer = "";
      performanceBoardMode = "";
      performanceCurrentWeek = "";
      performanceBoardSnapshot = null;
      orgToggle.textContent = "Login Org";
      orgToggle.classList.remove("is-authenticated");
      setState("Informe suas credenciais da org.");
      pendingLoginVerificationId = "";
      orgLoginVerificationIdInput.value = "";
      setLoginVerifyLead("");
      setMode("login");
      if (orgModeSwitch) {
        orgModeSwitch.classList.remove("hidden");
      }
      orgLogout.classList.add("hidden");
      orgLogout.hidden = true;
      if (orgOwnerTools) {
        orgOwnerTools.classList.add("hidden");
        orgOwnerTools.hidden = true;
      }
      if (orgAdvancedOps) {
        orgAdvancedOps.classList.add("hidden");
        orgAdvancedOps.hidden = true;
      }
      if (orgPasswordChange) {
        orgPasswordChange.classList.add("hidden");
        orgPasswordChange.hidden = true;
      }
      if (orgEmailChange) {
        orgEmailChange.classList.add("hidden");
        orgEmailChange.hidden = true;
      }
      if (orgMemberData) {
        orgMemberData.classList.add("hidden");
        orgMemberData.hidden = true;
      }
      setPerformanceShellVisibility(false);
      setPerformanceEditorVisibility(false);
      setPerformancePickerVisibility(false);
      setPerformanceTitle("Painel do jogador");
      setPerformanceHint("");
      if (orgPerformanceSummary) {
        orgPerformanceSummary.innerHTML = "";
      }
      if (orgPerformanceWeekly) {
        orgPerformanceWeekly.innerHTML = "";
      }
      if (orgPerformanceRanking) {
        orgPerformanceRanking.innerHTML = "";
      }
      if (orgEmailCurrent) {
        orgEmailCurrent.textContent = "-";
      }
      if (orgChip) {
        orgChip.classList.add("hidden");
        orgChip.hidden = true;
        orgChip.textContent = "";
      }
      resetEmailChangeFlow();
      syncDirectCreateRoleOptions();
      return;
    }

    const roleLabel = roleLabels[session.role] || "Membro";
    orgToggle.textContent = `${roleLabel} ${session.userNumber}`;
    orgToggle.classList.add("is-authenticated");

    const verificationText = session.emailVerifiedAt
      ? "E-mail confirmado."
      : "E-mail pendente de confirmação.";
    const passwordText = session.mustChangePassword
      ? "Troca de senha recomendada."
      : "Acesso autorizado.";
    setState(
      `Conectado como ${roleLabel} (credencial ${session.userNumber}). ${passwordText} ${verificationText}`
    );
    const roleClass = roleClassName(session.role);
    if (roleClass) {
      orgState.classList.add(roleClass);
    }

    if (orgChip) {
      orgChip.textContent = `${roleLabel} #${session.userNumber}`;
      orgChip.classList.remove("hidden");
      orgChip.hidden = false;
    }

    if (orgModeSwitch) {
      orgModeSwitch.classList.add("hidden");
    }
    orgModePanels.forEach((panel) => {
      panel.classList.add("hidden");
      panel.hidden = true;
    });
    orgLogout.classList.remove("hidden");
    orgLogout.hidden = false;
    if (orgPasswordChange) {
      orgPasswordChange.classList.remove("hidden");
      orgPasswordChange.hidden = false;
    }
    if (orgEmailChange) {
      orgEmailChange.classList.remove("hidden");
      orgEmailChange.hidden = false;
      resetEmailChangeFlow();
    }
    if (orgMemberData) {
      orgMemberData.classList.remove("hidden");
      orgMemberData.hidden = false;
      void refreshMemberDataPanel();
      void refreshPerformanceBoard();
      initPerformanceEvents();
    }
    if (orgEmailCurrent) {
      orgEmailCurrent.textContent = session.email || "-";
    }

    if (orgOwnerTools) {
      if (isApprovalRole(session.role)) {
        orgOwnerTools.classList.remove("hidden");
        orgOwnerTools.hidden = false;
        void refreshOwnerRequests();
        void refreshMemberStatuses();
      } else {
        orgOwnerTools.classList.add("hidden");
        orgOwnerTools.hidden = true;
      }
    }

    if (orgAdvancedOps) {
      const canUseAdvancedOps = isApprovalRole(session.role);
      orgAdvancedOps.classList.toggle("hidden", !canUseAdvancedOps);
      orgAdvancedOps.hidden = !canUseAdvancedOps;
    }
    if (orgOwnerAssume) {
      const canAssume = isFullManagementRole(session.role);
      orgOwnerAssume.classList.toggle("hidden", !canAssume);
      orgOwnerAssume.hidden = !canAssume;
    }
    syncDirectCreateRoleOptions();
  }

  sanitizeNumericInputs(orgAccessRoot);
  buildPerformanceScoreInputs();
  const verificationCodeInputs = [
    orgLoginVerifyForm.querySelector("input[name='code']"),
    orgEmailChangeConfirmForm.querySelector("input[name='code']")
  ].filter(Boolean);
  verificationCodeInputs.forEach((input) => {
    input.addEventListener("input", () => {
      const digits = String(input.value || "").replace(/\D+/g, "").slice(0, 6);
      if (digits !== input.value) {
        input.value = digits;
      }
    });
  });

  applySession(null);
  if (isOrgPage) {
    orgAccessRoot.classList.add("org-access-page");
    openPanel();
  } else {
    orgToggle.addEventListener("click", () => {
      const isHidden = orgPanel.classList.contains("hidden");
      if (isHidden) {
        openPanel();
        return;
      }

      closePanel();
    });
  }

  orgModeButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const mode = button.dataset.orgModeBtn;
      if (!mode || currentSession) {
        return;
      }

      setMode(mode);
    });
  });

  orgLoginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!orgLoginForm.checkValidity()) {
      orgLoginForm.reportValidity();
      return;
    }

    const formData = new FormData(orgLoginForm);
    const userNumber = String(formData.get("userNumber") || "").trim();
    const password = String(formData.get("password") || "");

    if (userNumber.length < 4 || password.length < 8) {
      setState("Credenciais inválidas. Revise número da credencial e senha.");
      return;
    }

    try {
      orgAuthInFlight = true;
      setState("Validando acesso da org...", "#9fd0ff");
      const { response, body } = await secureOrgRequest("/api/org/login", {
        method: "POST",
        body: JSON.stringify({
          userNumber,
          password
        })
      });

      if (!response.ok || !body?.ok || !body?.session) {
        if (response.status === 202 && body?.ok && body?.requiresEmailVerification && body?.verificationId) {
          pendingLoginVerificationId = String(body.verificationId);
          orgLoginVerificationIdInput.value = pendingLoginVerificationId;
          setLoginVerifyLead(body.email || "");
          orgLoginVerifyForm.reset();
          orgLoginVerificationIdInput.value = pendingLoginVerificationId;
          const debugMessage = body?.debugVerificationCode
            ? ` Codigo debug: ${body.debugVerificationCode}.`
            : "";
          setState(
            `${body.message || "Codigo enviado para o e-mail da conta."}${debugMessage}`,
            body?.debugVerificationCode ? "#ffcf9f" : "#9fd0ff"
          );
          setMode("login_verify");
          return;
        }

        setState(body?.error || "Falha no login da organização.", "#ffb3c0");
        return;
      }

      currentSession = body.session;
      orgSessionVersion += 1;
      applySession(currentSession);
      closePanel();
    } catch (error) {
      console.error(error);
      setState(String(error?.message || "Falha ao autenticar. Tente novamente."), "#ffb3c0");
    } finally {
      orgAuthInFlight = false;
    }
  });

  orgLoginVerifyForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!orgLoginVerifyForm.checkValidity()) {
      orgLoginVerifyForm.reportValidity();
      return;
    }

    const formData = new FormData(orgLoginVerifyForm);
    const verificationId = String(formData.get("verificationId") || "").trim();
    const code = String(formData.get("code") || "").trim();
    if (!verificationId || !/^[0-9]{6}$/.test(code)) {
      setState("Código de verificação inválido.", "#ffb3c0");
      return;
    }

    try {
      orgAuthInFlight = true;
      setState("Validando código de e-mail...", "#9fd0ff");
      const { response, body } = await secureOrgRequest("/api/org/login/confirm-email", {
        method: "POST",
        body: JSON.stringify({
          verificationId,
          code
        })
      });

      if (!response.ok || !body?.ok || !body?.session) {
        setState(body?.error || "Falha ao confirmar e-mail.", "#ffb3c0");
        return;
      }

      pendingLoginVerificationId = "";
      orgLoginVerificationIdInput.value = "";
      orgLoginVerifyForm.reset();
      currentSession = body.session;
      orgSessionVersion += 1;
      applySession(currentSession);
      closePanel();
    } catch (error) {
      console.error(error);
      setState("Falha ao confirmar código de e-mail.", "#ffb3c0");
    } finally {
      orgAuthInFlight = false;
    }
  });

  if (orgLoginVerifyBack) {
    orgLoginVerifyBack.addEventListener("click", () => {
      pendingLoginVerificationId = "";
      orgLoginVerificationIdInput.value = "";
      orgLoginVerifyForm.reset();
      setMode("login");
      setState("Login reiniciado. Informe credencial e senha para gerar novo código.", "#ffcf9f");
    });
  }

  if (orgRegisterForm && orgRegisterReview && orgRegisterReviewContent && orgRegisterAccept && orgRegisterReject) {
    orgRegisterForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!orgRegisterForm.checkValidity()) {
        orgRegisterForm.reportValidity();
        return;
      }

      const formData = new FormData(orgRegisterForm);
      pendingRegisterPayload = {
        fullName: String(formData.get("fullName") || "").trim(),
        email: String(formData.get("email") || "").trim().toLowerCase(),
        inGameName: String(formData.get("inGameName") || "").trim(),
        gameId: String(formData.get("gameId") || "").trim(),
        serverId: String(formData.get("serverId") || "").trim(),
        desiredRole: String(formData.get("desiredRole") || "").trim(),
        identificacaoGenero: String(formData.get("identificacaoGenero") || "").trim(),
        note: String(formData.get("note") || "").trim()
      };

      renderRegisterReview(pendingRegisterPayload);
      orgRegisterForm.classList.add("hidden");
      orgRegisterForm.hidden = true;
      orgRegisterReview.classList.remove("hidden");
      orgRegisterReview.hidden = false;
      setState("Revise os dados. Aceite para enviar para aprovação da liderança.", "#ffcf9f");
    });

    orgRegisterAccept.addEventListener("click", async () => {
      if (!pendingRegisterPayload) {
        setState("Nenhum cadastro para confirmar.", "#ffb3c0");
        return;
      }

      try {
        setState("Enviando cadastro para aprovação...", "#9fd0ff");
        const { response, body } = await secureOrgRequest("/api/org/register-request", {
          method: "POST",
          body: JSON.stringify(pendingRegisterPayload)
        });

        if (!response.ok || !body?.ok || !body?.requestId) {
          setState(body?.error || "Falha ao enviar cadastro para aprovação.", "#ffb3c0");
          return;
        }

        setState(body.message || "Cadastro enviado para aprovação da liderança.", "#9ff7d8");
        resetAllForms();
        setMode("login");
      } catch (error) {
        console.error(error);
        setState("Falha ao enviar cadastro para aprovação.", "#ffb3c0");
      }
    });

    orgRegisterReject.addEventListener("click", () => {
      pendingRegisterPayload = null;
      orgRegisterReview.classList.add("hidden");
      orgRegisterReview.hidden = true;
      orgRegisterReviewContent.innerHTML = "";
      orgRegisterForm.classList.remove("hidden");
      orgRegisterForm.hidden = false;
      setMode("register");
      setState("Cadastro cancelado. Você voltou para login/cadastro.", "#ffcf9f");
    });
  }

  function syncDirectCreateRoleOptions() {
    if (!orgDirectCreateForm) {
      return;
    }

    const roleSelect = orgDirectCreateForm.querySelector("select[name='role']");
    if (!roleSelect) {
      return;
    }

    const allowed = new Set(assignableRolesForRole(currentSession?.role));
    Array.from(roleSelect.options).forEach((option) => {
      if (!option.value) {
        option.hidden = false;
        option.disabled = false;
        return;
      }

      const isAllowed = allowed.has(option.value);
      option.hidden = !isAllowed;
      option.disabled = !isAllowed;
    });

    if (!allowed.has(roleSelect.value)) {
      roleSelect.value = "";
    }
  }

  if (orgDirectCreateForm) {
    orgDirectCreateForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      if (!currentSession || !isApprovalRole(currentSession.role)) {
        setState("Somente dono, líder, vice-líder e ADM podem cadastrar membros.", "#ffb3c0");
        return;
      }

      if (!orgDirectCreateForm.checkValidity()) {
        orgDirectCreateForm.reportValidity();
        return;
      }

      const formData = new FormData(orgDirectCreateForm);
      const payload = {
        fullName: String(formData.get("fullName") || "").trim(),
        email: String(formData.get("email") || "").trim().toLowerCase(),
        inGameName: String(formData.get("inGameName") || "").trim(),
        gameId: String(formData.get("gameId") || "").trim(),
        serverId: String(formData.get("serverId") || "").trim(),
        whatsapp: String(formData.get("whatsapp") || "").trim(),
        role: String(formData.get("role") || "").trim(),
        identificacaoGenero: String(formData.get("identificacaoGenero") || "").trim(),
        note: String(formData.get("note") || "").trim()
      };

      const allowedRoles = new Set(assignableRolesForRole(currentSession.role));
      if (!allowedRoles.has(payload.role)) {
        setState("Cargo inválido para o seu nível de acesso.", "#ffb3c0");
        return;
      }

      try {
        setState("Cadastrando membro e gerando credencial...", "#9fd0ff");
        const { response, body } = await secureOrgRequest("/api/org/admin/users/direct-create", {
          method: "POST",
          body: JSON.stringify(payload)
        });

        if (!response.ok || !body?.ok) {
          setState(body?.error || "Falha ao cadastrar membro diretamente.", "#ffb3c0");
          return;
        }

        const credential = body?.credentialNumber || body?.userNumber || "-";
        const tempPassword = body?.temporaryPassword || "-";
        setState(
          `Membro cadastrado. Credencial: ${credential}. Senha provisória: ${tempPassword}`,
          "#9ff7d8"
        );

        orgDirectCreateForm.reset();
        syncDirectCreateRoleOptions();
        if (orgOwnerTarget) {
          orgOwnerTarget.value = String(credential);
        }

        await refreshOwnerRequests();
        await refreshMemberStatuses();
        await refreshMemberDataPanel();
        await refreshPerformanceBoard(true);
      } catch (error) {
        console.error(error);
        setState("Falha ao cadastrar membro diretamente.", "#ffb3c0");
      }
    });
  }

  orgLogout.addEventListener("click", async () => {
    try {
      await secureOrgRequest("/api/org/logout", {
        method: "POST",
        body: JSON.stringify({})
      });
    } catch (error) {
      console.error(error);
    }

    currentSession = null;
    resetAllForms();
    applySession(null);
  });

  orgPasswordChangeForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!currentSession) {
      return;
    }

    if (!orgPasswordChangeForm.checkValidity()) {
      orgPasswordChangeForm.reportValidity();
      return;
    }

    const formData = new FormData(orgPasswordChangeForm);
    const payload = {
      currentPassword: String(formData.get("currentPassword") || ""),
      newPassword: String(formData.get("newPassword") || "")
    };

    try {
      setState("Atualizando senha da conta...", "#9fd0ff");
      const { response, body } = await secureOrgRequest("/api/org/password/change", {
        method: "POST",
        body: JSON.stringify(payload)
      });

      if (!response.ok || !body?.ok) {
        setState(body?.error || "Falha ao trocar senha.", "#ffb3c0");
        return;
      }

      setState(body.message || "Senha atualizada.", "#9ff7d8");
      orgPasswordChangeForm.reset();
    } catch (error) {
      console.error(error);
      setState("Falha ao trocar senha.", "#ffb3c0");
    }
  });

  orgEmailChangeRequestForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!currentSession) {
      return;
    }

    if (!orgEmailChangeRequestForm.checkValidity()) {
      orgEmailChangeRequestForm.reportValidity();
      return;
    }

    const formData = new FormData(orgEmailChangeRequestForm);
    const payload = {
      currentPassword: String(formData.get("currentPassword") || ""),
      newEmail: String(formData.get("newEmail") || "").trim().toLowerCase(),
      newEmailConfirm: String(formData.get("newEmailConfirm") || "").trim().toLowerCase()
    };

    if (!payload.newEmail || payload.newEmail !== payload.newEmailConfirm) {
      setState("Novo e-mail e confirmação devem ser iguais.", "#ffb3c0");
      return;
    }

    try {
      setState("Enviando código para confirmar novo e-mail...", "#9fd0ff");
      const { response, body } = await secureOrgRequest("/api/org/email/change/request", {
        method: "POST",
        body: JSON.stringify(payload)
      });

      if (!response.ok || !body?.ok || !body?.verificationId) {
        setState(body?.error || "Falha ao iniciar troca de e-mail.", "#ffb3c0");
        return;
      }

      orgEmailChangeVerificationIdInput.value = String(body.verificationId);
      if (orgEmailChangeRequestBox) {
        orgEmailChangeRequestBox.classList.add("hidden");
        orgEmailChangeRequestBox.hidden = true;
      }
      if (orgEmailChangeConfirmBox) {
        orgEmailChangeConfirmBox.classList.remove("hidden");
        orgEmailChangeConfirmBox.hidden = false;
      }
      orgEmailChangeConfirmForm.reset();
      orgEmailChangeVerificationIdInput.value = String(body.verificationId);

      const debugMessage = body?.debugVerificationCode
        ? ` Codigo debug: ${body.debugVerificationCode}.`
        : "";
      setState(`${body.message || "Codigo enviado para o novo e-mail."}${debugMessage}`, body?.debugVerificationCode ? "#ffcf9f" : "#9fd0ff");
    } catch (error) {
      console.error(error);
      setState("Falha ao solicitar troca de e-mail.", "#ffb3c0");
    }
  });

  orgEmailChangeConfirmForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!currentSession) {
      return;
    }

    if (!orgEmailChangeConfirmForm.checkValidity()) {
      orgEmailChangeConfirmForm.reportValidity();
      return;
    }

    const formData = new FormData(orgEmailChangeConfirmForm);
    const payload = {
      verificationId: String(formData.get("verificationId") || "").trim(),
      code: String(formData.get("code") || "").trim()
    };

    try {
      setState("Confirmando novo e-mail...", "#9fd0ff");
      const { response, body } = await secureOrgRequest("/api/org/email/change/confirm", {
        method: "POST",
        body: JSON.stringify(payload)
      });

      if (!response.ok || !body?.ok) {
        setState(body?.error || "Falha ao confirmar novo e-mail.", "#ffb3c0");
        return;
      }

      if (body?.session) {
        currentSession = body.session;
      } else if (currentSession && payload.verificationId) {
        const requestedEmail = String(
          orgEmailChangeRequestForm.querySelector("input[name='newEmail']")?.value || ""
        )
          .trim()
          .toLowerCase();
        if (requestedEmail) {
          currentSession.email = requestedEmail;
          currentSession.emailVerifiedAt = new Date().toISOString();
        }
      }

      applySession(currentSession);
      setState(body.message || "E-mail atualizado com sucesso.", "#9ff7d8");
    } catch (error) {
      console.error(error);
      setState("Falha ao confirmar troca de e-mail.", "#ffb3c0");
    }
  });

  if (orgEmailChangeCancel) {
    orgEmailChangeCancel.addEventListener("click", () => {
      resetEmailChangeFlow();
      setState("Troca de e-mail cancelada.", "#ffcf9f");
    });
  }

  if (orgOwnerRefresh) {
    orgOwnerRefresh.addEventListener("click", () => {
      void refreshOwnerRequests();
    });
  }

  if (orgMembersRefresh) {
    orgMembersRefresh.addEventListener("click", () => {
      void refreshMemberStatuses();
    });
  }

  if (orgMemberDataRefresh) {
    orgMemberDataRefresh.addEventListener("click", () => {
      void refreshMemberDataPanel();
      void refreshPerformanceBoard();
    });
  }

  if (orgPerformanceRefresh) {
    orgPerformanceRefresh.addEventListener("click", () => {
      void refreshPerformanceBoard();
    });
  }

  if (orgPerformancePlayerSelect) {
    orgPerformancePlayerSelect.addEventListener("change", () => {
      const playerUserNumber = String(orgPerformancePlayerSelect.value || "").trim();
      if (!playerUserNumber) {
        return;
      }

      performanceSelectedPlayer = playerUserNumber;
      if (orgPerformancePlayerInput) {
        orgPerformancePlayerInput.value = playerUserNumber;
      }
      void loadPerformancePlayer(playerUserNumber);
    });
  }

  if (orgPerformanceForm) {
    orgPerformanceForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!currentSession || !isPerformanceEditorRole(currentSession.role)) {
        setState("Seu cargo não possui permissão para atualizar desempenho.", "#ffb3c0");
        return;
      }

      if (!orgPerformanceForm.checkValidity()) {
        orgPerformanceForm.reportValidity();
        return;
      }

      const formData = new FormData(orgPerformanceForm);
      const playerUserNumber = String(formData.get("playerUserNumber") || "").trim();
      if (!/^[0-9]{4,12}$/.test(playerUserNumber)) {
        setState("Selecione um player válido para salvar a atualização.", "#ffb3c0");
        return;
      }

      const week = String(formData.get("week") || "").trim();
      const payload = {
        playerUserNumber,
        scores: readPerformanceFormScores(),
        strengths: parsePerformanceBullets(formData.get("strengths")),
        improvements: parsePerformanceBullets(formData.get("improvements")),
        note: String(formData.get("note") || "").trim()
      };
      if (week) {
        payload.week = week;
      }

      try {
        setState("Salvando atualização semanal do jogador...", "#9fd0ff");
        const { response, body } = await secureOrgRequest("/api/org/performance/updates", {
          method: "POST",
          body: JSON.stringify(payload)
        });

        if (!response.ok || !body?.ok) {
          setState(body?.error || "Falha ao salvar atualização de desempenho.", "#ffb3c0");
          return;
        }

        performanceSelectedPlayer = playerUserNumber;
        setState("Atualização de desempenho salva com sucesso.", "#9ff7d8");
        await refreshPerformanceBoard(true);
      } catch (error) {
        console.error(error);
        setState("Falha ao salvar atualização de desempenho.", "#ffb3c0");
      }
    });
  }

  if (orgOwnerList) {
    orgOwnerList.addEventListener("click", async (event) => {
      const target = event.target.closest("button[data-action][data-request-id]");
      if (!target || !currentSession || !isApprovalRole(currentSession.role)) {
        return;
      }

      const requestId = String(target.dataset.requestId || "");
      const action = String(target.dataset.action || "");
      if (!requestId || !action) {
        return;
      }

      try {
        if (action === "approve") {
          setState("Aprovando cadastro...", "#9fd0ff");
          const suggestedRole = String(target.dataset.role || "player");
          const allowedRolesByActor = assignableRolesForRole(currentSession.role);
          const fallbackRole = allowedRolesByActor.includes(suggestedRole)
            ? suggestedRole
            : allowedRolesByActor[0] || "player";
          const enteredRole = window.prompt(
            `Defina o cargo final permitido para seu nivel (${allowedRolesByActor.join(", ")}):`,
            fallbackRole
          );
          if (!enteredRole) {
            setState("Aprovação cancelada.", "#ffcf9f");
            return;
          }

          const chosenRole = String(enteredRole).trim().toLowerCase();
          const allowedRoles = new Set(allowedRolesByActor);
          if (!allowedRoles.has(chosenRole)) {
            setState("Cargo final inválido para o seu nível de acesso.", "#ffb3c0");
            return;
          }

          const { response, body } = await secureOrgRequest(
            `/api/org/admin/requests/${encodeURIComponent(requestId)}/approve`,
            {
              method: "POST",
              body: JSON.stringify({ finalRole: chosenRole })
            }
          );

          if (!response.ok || !body?.ok) {
            setState(body?.error || "Falha ao aprovar cadastro.", "#ffb3c0");
            return;
          }

          const tempMessage = body?.temporaryPassword
            ? ` Senha inicial: ${body.temporaryPassword}`
            : "";
          setState(`Aprovado: credencial ${body.userNumber}.${tempMessage}`, "#9ff7d8");
          await refreshOwnerRequests();
          await refreshMemberStatuses();
          await refreshPerformanceBoard(true);
          return;
        }

        if (action === "reject") {
          const reason = window.prompt(
            "Motivo da reprovação (opcional):",
            "Não aprovado pela liderança."
          );
          if (reason === null) {
            setState("Reprovação cancelada.", "#ffcf9f");
            return;
          }

          const { response, body } = await secureOrgRequest(
            `/api/org/admin/requests/${encodeURIComponent(requestId)}/reject`,
            {
              method: "POST",
              body: JSON.stringify({ reason: String(reason || "").trim() })
            }
          );

          if (!response.ok || !body?.ok) {
            setState(body?.error || "Falha ao reprovar cadastro.", "#ffb3c0");
            return;
          }

          setState("Cadastro reprovado.", "#ffcf9f");
          await refreshOwnerRequests();
          await refreshMemberStatuses();
        }
      } catch (error) {
        console.error(error);
        setState("Falha na análise de cadastro.", "#ffb3c0");
      }
    });
  }

  if (orgMembersList) {
    orgMembersList.addEventListener("click", async (event) => {
      const target = event.target.closest("button[data-member-action][data-member-user-number]");
      if (!target || !currentSession || !isApprovalRole(currentSession.role)) {
        return;
      }

      const action = String(target.dataset.memberAction || "");
      const memberUserNumber = String(target.dataset.memberUserNumber || "");
      if (!action || !/^[0-9]{4,12}$/.test(memberUserNumber)) {
        return;
      }

      if (action === "remind-email") {
        try {
          setState(`Enviando lembrete para credencial ${memberUserNumber}...`, "#9fd0ff");
          const { response, body } = await secureOrgRequest(
            `/api/org/admin/users/${encodeURIComponent(memberUserNumber)}/remind-email-verification`,
            {
              method: "POST",
              body: JSON.stringify({})
            }
          );

          if (!response.ok || !body?.ok) {
            setState(body?.error || "Falha ao enviar lembrete de verificação.", "#ffb3c0");
            return;
          }

          setState(body.message || "Lembrete enviado com sucesso.", "#9ff7d8");
          await refreshMemberStatuses();
        } catch (error) {
          console.error(error);
          setState("Falha ao enviar lembrete de verificação.", "#ffb3c0");
        }
        return;
      }

      if (action === "change-role") {
        const currentRole = String(target.dataset.memberRole || "").trim();
        const allowedRoles = assignableRolesForRole(currentSession.role);
        const defaultRole = allowedRoles.includes(currentRole)
          ? currentRole
          : allowedRoles[0] || "player";

        const enteredRole = window.prompt(
          `Novo cargo para a credencial ${memberUserNumber} (${allowedRoles.join(", ")}):`,
          defaultRole
        );
        if (!enteredRole) {
          setState("Atualização de cargo cancelada.", "#ffcf9f");
          return;
        }

        const nextRole = String(enteredRole || "").trim().toLowerCase();
        if (!allowedRoles.includes(nextRole)) {
          setState("Cargo inválido para o seu nível de acesso.", "#ffb3c0");
          return;
        }

        try {
          setState(`Atualizando cargo da credencial ${memberUserNumber}...`, "#9fd0ff");
          const { response, body } = await secureOrgRequest(
            `/api/org/admin/users/${encodeURIComponent(memberUserNumber)}/update-role`,
            {
              method: "POST",
              body: JSON.stringify({ role: nextRole })
            }
          );

          if (!response.ok || !body?.ok) {
            setState(body?.error || "Falha ao atualizar cargo do membro.", "#ffb3c0");
            return;
          }

          setState(body.message || "Cargo atualizado com sucesso.", "#9ff7d8");
          await refreshMemberStatuses();
          await refreshMemberDataPanel();
          await refreshPerformanceBoard(true);
        } catch (error) {
          console.error(error);
          setState("Falha ao atualizar cargo do membro.", "#ffb3c0");
        }
        return;
      }

      if (action === "remove-member") {
        const memberRole = String(target.dataset.memberRole || "").trim();
        const confirmRemove = window.confirm(
          `Confirmar remoção da credencial ${memberUserNumber} (${roleLabelFromValue(memberRole)})?`
        );
        if (!confirmRemove) {
          setState("Remoção de membro cancelada.", "#ffcf9f");
          return;
        }

        const reasonInput = window.prompt(
          "Motivo da remoção (opcional):",
          "Desligamento da organização."
        );
        if (reasonInput === null) {
          setState("Remoção de membro cancelada.", "#ffcf9f");
          return;
        }

        try {
          setState(`Removendo credencial ${memberUserNumber}...`, "#9fd0ff");
          const { response, body } = await secureOrgRequest(
            `/api/org/admin/users/${encodeURIComponent(memberUserNumber)}/remove`,
            {
              method: "POST",
              body: JSON.stringify({ reason: String(reasonInput || "").trim() })
            }
          );

          if (!response.ok || !body?.ok) {
            setState(body?.error || "Falha ao remover membro.", "#ffb3c0");
            return;
          }

          setState(body.message || "Membro removido com sucesso.", "#9ff7d8");
          await refreshMemberStatuses();
          await refreshMemberDataPanel();
          await refreshPerformanceBoard(true);
        } catch (error) {
          console.error(error);
          setState("Falha ao remover membro.", "#ffb3c0");
        }
      }
    });
  }

  async function runOwnerDirectAction(actionType) {
    if (!currentSession || !orgOwnerTarget) {
      return;
    }

    const canAssume = isFullManagementRole(currentSession.role);
    const canManageCredentials = isApprovalRole(currentSession.role);
    if (actionType === "assume" && !canAssume) {
      setState("Somente dono e líder podem assumir conta.", "#ffb3c0");
      return;
    }
    if ((actionType === "force-reset" || actionType === "change-credential") && !canManageCredentials) {
      setState("Somente dono, líder, vice-líder e ADM podem gerir credenciais e senha.", "#ffb3c0");
      return;
    }

    const targetUserNumber = String(orgOwnerTarget.value || "").trim();
    if (!/^[0-9]{4,12}$/.test(targetUserNumber)) {
      setState("Informe uma credencial válida para a ação.", "#ffb3c0");
      return;
    }

    try {
      if (actionType === "assume") {
        setState(`Assumindo acesso da credencial ${targetUserNumber}...`, "#9fd0ff");
        const { response, body } = await secureOrgRequest(
          `/api/org/admin/users/${encodeURIComponent(targetUserNumber)}/assume`,
          {
            method: "POST",
            body: JSON.stringify({})
          }
        );

        if (!response.ok || !body?.ok || !body?.session) {
          setState(body?.error || "Falha ao assumir conta.", "#ffb3c0");
          return;
        }

        currentSession = body.session;
        applySession(currentSession);
        setState(
          `Sessão alterada para credencial ${currentSession.userNumber}. Refaça login como líder/dono para voltar.`,
          "#ffcf9f"
        );
        closePanel();
        return;
      }

      if (actionType === "force-reset") {
        const customPassword = window.prompt(
          "Nova senha para a credencial alvo (min. 8 caracteres). Deixe vazio para gerar senha automática:",
          ""
        );
        if (customPassword === null) {
          setState("Reset de senha cancelado.", "#ffcf9f");
          return;
        }
        const newPassword = String(customPassword || "").trim();
        if (newPassword && newPassword.length < 8) {
          setState("A nova senha precisa ter no mínimo 8 caracteres.", "#ffb3c0");
          return;
        }

        setState(`Resetando senha da credencial ${targetUserNumber}...`, "#9fd0ff");
        const { response, body } = await secureOrgRequest(
          `/api/org/admin/users/${encodeURIComponent(targetUserNumber)}/force-reset`,
          {
            method: "POST",
            body: JSON.stringify(newPassword ? { newPassword } : {})
          }
        );

        if (!response.ok || !body?.ok) {
          setState(body?.error || "Falha ao resetar senha da credencial.", "#ffb3c0");
          return;
        }

        const tempMessage = body?.temporaryPassword
          ? ` Senha inicial: ${body.temporaryPassword}`
          : "";
        setState(`Senha resetada para credencial ${targetUserNumber}.${tempMessage}`, "#9ff7d8");
        await refreshMemberStatuses();
        await refreshMemberDataPanel();
        await refreshPerformanceBoard(true);
        return;
      }

      if (actionType === "change-credential") {
        if (!orgOwnerNewCredential) {
          setState("Campo de nova credencial não encontrado.", "#ffb3c0");
          return;
        }

        const newCredentialNumber = String(orgOwnerNewCredential.value || "").trim();
        if (!/^[0-9]{4,12}$/.test(newCredentialNumber)) {
          setState("Informe uma nova credencial válida (4 a 12 dígitos).", "#ffb3c0");
          return;
        }

        setState(
          `Atualizando credencial ${targetUserNumber} para ${newCredentialNumber}...`,
          "#9fd0ff"
        );
        const { response, body } = await secureOrgRequest(
          `/api/org/admin/users/${encodeURIComponent(targetUserNumber)}/change-credential`,
          {
            method: "POST",
            body: JSON.stringify({ newCredentialNumber })
          }
        );

        if (!response.ok || !body?.ok) {
          setState(body?.error || "Falha ao atualizar credencial.", "#ffb3c0");
          return;
        }

        orgOwnerTarget.value = String(body.credentialNumber || "");
        orgOwnerNewCredential.value = "";
        setState(
          body.message || `Credencial alterada de ${targetUserNumber} para ${body.credentialNumber}.`,
          "#9ff7d8"
        );
        await refreshMemberStatuses();
        await refreshMemberDataPanel();
        await refreshPerformanceBoard(true);
      }
    } catch (error) {
      console.error(error);
      setState("Falha na operação de gestão.", "#ffb3c0");
    }
  }

  if (orgOwnerAssume) {
    orgOwnerAssume.addEventListener("click", () => {
      void runOwnerDirectAction("assume");
    });
  }

  if (orgOwnerForceReset) {
    orgOwnerForceReset.addEventListener("click", () => {
      void runOwnerDirectAction("force-reset");
    });
  }

  if (orgOwnerChangeCredential) {
    orgOwnerChangeCredential.addEventListener("click", () => {
      void runOwnerDirectAction("change-credential");
    });
  }

  syncDirectCreateRoleOptions();

  async function restoreOrgSession(clearOnFailure = true) {
    const restoreVersion = orgSessionVersion;
    try {
      const { response, body } = await secureOrgRequest("/api/org/session", { method: "GET" });
      if (!response.ok || !body?.ok || !body?.session) {
        if (clearOnFailure && !currentSession && !orgAuthInFlight && restoreVersion === orgSessionVersion) {
          applySession(null);
        }
        return;
      }

      currentSession = body.session;
      orgSessionVersion += 1;
      applySession(currentSession);
    } catch (_error) {
      if (clearOnFailure && !currentSession && !orgAuthInFlight && restoreVersion === orgSessionVersion) {
        applySession(null);
      }
    }
  }

  void restoreOrgSession();

  if (!isOrgPage) {
    document.addEventListener("click", (event) => {
      if (orgPanel.classList.contains("hidden")) {
        return;
      }

      if (orgAccessRoot.contains(event.target)) {
        return;
      }

      closePanel();
    });

    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") {
        return;
      }

      closePanel();
    });
  }
}

function initOrgEmailVerificationPage() {
  const verificationForm = document.querySelector("[data-org-email-verification-form]");
  const verificationState = document.querySelector("[data-org-email-verification-state]");
  const verificationLead = document.querySelector("[data-org-email-verification-lead]");
  const verificationIdInput = document.querySelector("[data-org-verification-id]");

  if (!verificationForm || !verificationState || !verificationIdInput) {
    return;
  }

  function setVerificationState(message, color = "") {
    verificationState.textContent = message;
    verificationState.style.color = color;
  }

  const params = new URLSearchParams(window.location.search);
  const verificationId = String(params.get("verificationId") || "").trim();
  const email = String(params.get("email") || "").trim().toLowerCase();

  if (!verificationId) {
    setVerificationState("Link de verificação inválido. Volte para login/cadastro.", "#ffb3c0");
    return;
  }

  verificationIdInput.value = verificationId;
  if (verificationLead && email) {
    verificationLead.textContent =
      `Digite o código de 6 dígitos enviado para ${email} para validar seu e-mail.`;
  }

  const codeInput = verificationForm.querySelector("input[name='code']");
  if (codeInput) {
    codeInput.addEventListener("input", () => {
      const digits = codeInput.value.replace(/\D+/g, "").slice(0, 6);
      if (digits !== codeInput.value) {
        codeInput.value = digits;
      }
    });
  }

  async function secureRequest(path, options = {}) {
    let context = await loadSecurityContext();
    const headers = {
      Accept: "application/json",
      ...(options.headers || {})
    };

    if (options.body && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }

    headers["X-CSRF-Token"] = context.csrfToken;

    let response = await fetch(path, {
      ...options,
      credentials: "include",
      headers
    });

    if (response.status === 403) {
      context = await loadSecurityContext(true);
      response = await fetch(path, {
        ...options,
        credentials: "include",
        headers: {
          ...headers,
          "X-CSRF-Token": context.csrfToken
        }
      });
    }

    const body = await response.json().catch(() => ({}));
    return { response, body };
  }

  verificationForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!verificationForm.checkValidity()) {
      verificationForm.reportValidity();
      return;
    }

    const formData = new FormData(verificationForm);
    const payload = {
      verificationId: String(formData.get("verificationId") || "").trim(),
      code: String(formData.get("code") || "").trim()
    };

    try {
      setVerificationState("Validando código de e-mail...", "#9fd0ff");
      const { response, body } = await secureRequest("/api/org/register-request/confirm-email", {
        method: "POST",
        body: JSON.stringify(payload)
      });

      if (!response.ok || !body?.ok) {
        setVerificationState(body?.error || "Falha ao validar código.", "#ffb3c0");
        return;
      }

      setVerificationState(
        `${body.message || "E-mail validado."} Redirecionando para login/cadastro...`,
        "#9ff7d8"
      );
      window.setTimeout(() => {
        window.location.href = "login.html";
      }, 1300);
    } catch (error) {
      console.error(error);
      setVerificationState("Falha ao confirmar código de e-mail.", "#ffb3c0");
    }
  });
}

async function postEncryptedSubmission(payload, csrfToken) {
  const response = await fetch("/api/recruitment", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken
    },
    body: JSON.stringify(payload)
  });

  const body = await response.json().catch(() => ({}));
  return { response, body };
}

async function handleSubmit(event) {
  event.preventDefault();

  if (!window.isSecureContext || !window.crypto?.subtle) {
    setFeedback("Use HTTPS para enviar com criptografia de ponta a ponta.", "#ffb3c0");
    return;
  }

  if (!form.checkValidity()) {
    setFeedback("Preencha todos os campos obrigatorios antes de enviar.", "#ffb3c0");
    form.reportValidity();
    return;
  }

  const formData = new FormData(form);
  const honeypot = getString(formData, "website");
  const payload = collectFormPayload(formData);

  try {
    setFeedback("Aplicando criptografia e enviando com segurança...", "#9fd0ff");

    let context = await loadSecurityContext();
    let envelope = await encryptSubmission(context.publicKey, payload);

    let requestBody = {
      honeypot,
      envelope,
      client: {
        keyId: context.keyId,
        appVersion: "1.0.0"
      }
    };

    let { response, body } = await postEncryptedSubmission(requestBody, context.csrfToken);

    if (response.status === 403) {
      context = await loadSecurityContext(true);
      envelope = await encryptSubmission(context.publicKey, payload);
      requestBody = {
        honeypot,
        envelope,
        client: {
          keyId: context.keyId,
          appVersion: "1.0.0"
        }
      };

      ({ response, body } = await postEncryptedSubmission(requestBody, context.csrfToken));
    }

    if (!response.ok || !body?.ok) {
      const errorMessage = body?.error || "Falha de segurança no envio. Tente novamente.";
      setFeedback(errorMessage, "#ffb3c0");
      return;
    }

    setFeedback(
      `Inscricao recebida com criptografia ponta a ponta. Protocolo: ${body.submissionId}`,
      "#9ff7d8"
    );
    form.reset();
  } catch (error) {
    console.error(error);
    setFeedback("Falha ao enviar com segurança. Tente novamente em instantes.", "#ffb3c0");
  }
}

if (form && feedback) {
  numericOnlyInputs.forEach((input) => {
    input.addEventListener("input", () => {
      const sanitized = input.value.replace(/\D+/g, "");
      if (input.value !== sanitized) {
        input.value = sanitized;
      }
    });
  });

  form.addEventListener("submit", handleSubmit);

  loadSecurityContext().catch(() => {
    // Pré-carga silenciosa: não exibir mensagem visual se falhar.
  });
}
