(() => {
  const supportsMatchMedia = typeof window.matchMedia === "function";
  const coarsePointer =
    supportsMatchMedia && window.matchMedia("(hover: none) and (pointer: coarse)").matches;
  const saveData = Boolean(navigator.connection && navigator.connection.saveData);
  const lowEndDevice =
    Number(navigator.hardwareConcurrency || 8) <= 4 || Number(navigator.deviceMemory || 8) <= 4;

  // Skip heavy anti-inspect routines on mobile / low-end devices.
  if (coarsePointer || saveData || lowEndDevice) {
    return;
  }

  const isBlockedCombo = (event) => {
    const key = String(event.key || "").toUpperCase();
    const ctrlOrMeta = event.ctrlKey || event.metaKey;

    if (key === "F12") {
      return true;
    }

    if (ctrlOrMeta && event.shiftKey && ["I", "J", "C"].includes(key)) {
      return true;
    }

    if (ctrlOrMeta && key === "U") {
      return true;
    }

    return false;
  };

  let overlay = null;

  const ensureOverlay = () => {
    if (overlay || !document.body) {
      return;
    }

    overlay = document.createElement("div");
    overlay.className = "anti-inspect-overlay";
    overlay.setAttribute("aria-live", "polite");
    overlay.innerHTML =
      "<div><h2>Acesso restrito</h2><p>Ferramentas de inspecao foram detectadas. Recarregue a pagina para continuar.</p></div>";
    document.body.appendChild(overlay);
  };

  const activateShield = () => {
    ensureOverlay();
    document.documentElement.classList.add("inspect-blocked");
  };

  document.addEventListener("contextmenu", (event) => {
    event.preventDefault();
  });

  document.addEventListener("keydown", (event) => {
    if (!isBlockedCombo(event)) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
  });

  let detectionHits = 0;
  const threshold = 160;
  let intervalId = null;

  const detectDevtools = () => {
    const widthGap = Math.abs(window.outerWidth - window.innerWidth);
    const heightGap = Math.abs(window.outerHeight - window.innerHeight);
    const isLikelyOpen = widthGap > threshold || heightGap > threshold;

    if (!isLikelyOpen) {
      detectionHits = Math.max(0, detectionHits - 1);
      return;
    }

    detectionHits += 1;
    if (detectionHits >= 2) {
      activateShield();
    }
  };

  const startDetector = () => {
    if (intervalId !== null) {
      return;
    }
    intervalId = window.setInterval(detectDevtools, 3000);
  };

  const stopDetector = () => {
    if (intervalId === null) {
      return;
    }
    window.clearInterval(intervalId);
    intervalId = null;
  };

  window.addEventListener("resize", detectDevtools, { passive: true });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      stopDetector();
      return;
    }
    startDetector();
  });

  if (!document.hidden) {
    startDetector();
  }
})();
