// ---------- Network config (subnet / gateway) ----------
const gatewayInput = document.getElementById("gatewayInput");
const subnetInput  = document.getElementById("subnetInput");
const scanBtn      = document.getElementById("scanBtn");
const scanStatus   = document.getElementById("scanStatus");

async function loadNetworkConfig() {
    try {
        const res = await fetch("/api/config/network");
        if (!res.ok) return;
        const cfg = await res.json();
        if (cfg.gateway_ip) gatewayInput.value = cfg.gateway_ip;
        if (cfg.subnet)     subnetInput.value  = cfg.subnet;
    } catch (err) {
        console.error("loadNetworkConfig failed:", err);
    }
}

async function saveNetworkConfig() {
    const payload = {
        subnet:     (subnetInput.value  || "").trim(),
        gateway_ip: (gatewayInput.value || "").trim(),
    };
    if (!payload.subnet && !payload.gateway_ip) return true;

    try {
        const res = await fetch("/api/config/network", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify(payload),
        });
        const body = await res.json();
        if (!res.ok) {
            scanStatus.textContent = "⚠ " + (body.error || "save failed");
            return false;
        }
        gatewayInput.value = body.gateway_ip;
        subnetInput.value  = body.subnet;
        return true;
    } catch (err) {
        scanStatus.textContent = "⚠ network error";
        return false;
    }
}

gatewayInput?.addEventListener("blur", saveNetworkConfig);
subnetInput ?.addEventListener("blur", saveNetworkConfig);

async function runDiscovery() {
    scanStatus.textContent = "Saving settings…";
    const ok = await saveNetworkConfig();
    if (!ok) return;

    scanStatus.textContent = "Scanning…";
    scanBtn.disabled = true;

    try {
        const res = await fetch("/api/discovery", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ subnet: subnetInput.value.trim() }),
        });
        const body = await res.json();
        if (!res.ok) throw new Error(body.error || "discovery failed");

        scanStatus.textContent =
            `✔ ${body.total_discovered} device(s) found — opening dashboard…`;

        // ⬇️ This is the "open monitor dashboard" step
        window.location.replace("/dashboard");
    } catch (err) {
        scanStatus.textContent = "⚠ " + err.message;
        scanBtn.disabled = false;
    }
}

scanBtn?.addEventListener("click", runDiscovery);

loadNetworkConfig();