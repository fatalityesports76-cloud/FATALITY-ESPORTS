(() => {
  const blockedCombo = (event) => {
    const key = String(event.key || "").toUpperCase();
    const ctrl = event.ctrlKey || event.metaKey;

    if (key === "F12") {
      return true;
    }

    if (ctrl && event.shiftKey && ["I", "J", "C"].includes(key)) {
      return true;
    }

    if (ctrl && key === "U") {
      return true;
    }

    return false;
  };

  const overlay = document.createElement("div");
  overlay.className = "anti-inspect-overlay";
  overlay.setAttribute("aria-live", "polite");
  overlay.innerHTML =
    "<div><h2>Acesso restrito</h2><p>Ferramentas de inspecao foram detectadas. Recarregue a pagina para continuar.</p></div>";
  document.addEventListener("DOMContentLoaded", () => {
    document.body.appendChild(overlay);
  });

  const activateShield = () => {
    document.documentElement.classList.add("inspect-blocked");
  };

  document.addEventListener("contextmenu", (event) => {
    event.preventDefault();
  });

  document.addEventListener("keydown", (event) => {
    if (!blockedCombo(event)) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
  });

  let detectionHits = 0;
  const threshold = 160;

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

  window.addEventListener("resize", detectDevtools);
  setInterval(detectDevtools, 1000);
})();
