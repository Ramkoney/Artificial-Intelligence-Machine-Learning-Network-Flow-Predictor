"use strict";

// --- GLOBAL STATE FOR NETWORK HEALTH ---
let currentAttackCount = 0;
let currentUnknownCount = 0;

// --- LOGOUT ---
const logoutBtn = document.querySelector('[data-page="logout"]');

logoutBtn?.addEventListener("click", async () => {
    try {
        await fetch("/api/auth/logout", {
            method: "POST",
            credentials: "same-origin"
        });
    } catch (error) {
        console.error("Logout request failed:", error);
    }
    window.location.href = "/login";
});

// --- PAGE NAVIGATION ---
const titles = {
    overview: "Security Overview",
    monitoring: "Network Monitoring",
    intrusion: "AI Intrusion Detection",
    alerts: "Security Information"
};

function showPage(pageId) {
    if (!titles[pageId]) return;

    document.querySelectorAll(".page").forEach(page => {
        page.classList.toggle("active", page.id === pageId);
    });

    document.querySelectorAll("[data-page]").forEach(button => {
        button.classList.toggle("active", button.dataset.page === pageId);
    });

    document.getElementById("pageTitle").textContent = titles[pageId];
    history.replaceState(null, "", "#" + pageId);

    if (pageId === "alerts") {
        loadUnknownDevices();
    }
}

document.querySelectorAll("[data-page]").forEach(button => {
    button.addEventListener("click", () => {
        if (button.dataset.page !== "logout") {
            showPage(button.dataset.page);
        }
    });
});

document.querySelectorAll("[data-go]").forEach(button => {
    button.addEventListener("click", () => showPage(button.dataset.go));
});

const initialPage = location.hash.slice(1);
if (titles[initialPage]) {
    showPage(initialPage);
}

// --- AI ATTACK ALERTS ---
const attackAlerts = document.getElementById("attackAlerts");
const securityAttackCount = document.getElementById("securityAttackCount");
const clearAttackAlertsButton = document.getElementById("clearAttackAlerts");

let latestAttackResults = [];
let alertSequence = 0;

function getSecurityPrediction(data) {
    return String(
        data.prediction ?? data.label ?? data.result ?? 
        data.classification ?? data.attack_type ?? ""
    ).trim();
}

function isSecurityAttack(data) {
    const prediction = getSecurityPrediction(data).toLowerCase();
    if (!prediction) return false;

    const normalLabels = [
        "normal", "benign", "normal traffic", "non-attack",
        "non attack", "safe", "0", "false"
    ];

    if (normalLabels.includes(prediction)) return false;
    if (prediction === "1") return true;

    return (
        prediction.includes("attack") || prediction.includes("malicious") ||
        prediction.includes("intrusion") || prediction.includes("anomaly") ||
        prediction.includes("port scan") || prediction.includes("brute force") ||
        prediction.includes("flood") || prediction.includes("exfiltration")
    );
}

function createAttackCard(data, index) {
    const card = document.createElement("article");
    card.className = "card alert-card";

    const heading = document.createElement("h3");
    heading.className = "red";
    heading.textContent = " AI Attack Detected";

    const prediction = document.createElement("p");
    prediction.textContent = "Prediction: " + (getSecurityPrediction(data) || "Attack");

    const scenario = document.createElement("p");
    scenario.textContent = "Scenario: " + (data.scenario || data.attack_type || data.name || "N/A");

    const source = document.createElement("p");
    source.textContent = "Source IP: " + (data.src_ip || data.source_ip || data.src || "N/A");

    const destination = document.createElement("p");
    destination.textContent = "Destination IP: " + (data.dst_ip || data.destination_ip || data.dst || "N/A");

    const timestamp = document.createElement("p");
    timestamp.textContent = "Time: " + (data.timestamp || data.time || new Date().toLocaleString());

    const confidence = document.createElement("p");
    let confidenceValue = "Not provided";
    if (data.confidence_percent != null) {
        confidenceValue = `${data.confidence_percent}%`;
    } else if (data.confidence != null || data.probability != null) {
        const raw = Number(data.confidence ?? data.probability);
        if (Number.isFinite(raw)) {
            confidenceValue = `${(raw <= 1 ? raw * 100 : raw).toFixed(2)}%`;
        }
    }
    confidence.textContent = "Confidence: " + confidenceValue;

    const alertNumber = document.createElement("p");
    alertNumber.className = "muted";
    alertNumber.textContent = `Alert #${index}`;

    card.append(heading, prediction, scenario, source, destination, timestamp, confidence, alertNumber);
    return card;
}

function renderSecurityAttackAlerts() {
    const attacksOnly = latestAttackResults.filter(isSecurityAttack);
    securityAttackCount.textContent = String(attacksOnly.length);
    
    // Update global health metric
    currentAttackCount = attacksOnly.length;
    updateNetworkHealth();

    if (attacksOnly.length === 0) {
        const message = document.createElement("p");
        message.className = "muted alert-empty";
        message.textContent = "No attack predictions received yet.";
        attackAlerts.replaceChildren(message);
        return;
    }

    const fragment = document.createDocumentFragment();
    attacksOnly.forEach((data, index) => {
        fragment.appendChild(createAttackCard(data, index + 1));
    });
    attackAlerts.replaceChildren(fragment);
}

function receiveAttackResult(result) {
    if (!result || typeof result !== "object" || Array.isArray(result)) return;
    if (!isSecurityAttack(result)) return;

    const suppliedId = result.alert_id ?? result.id ?? null;
    if (suppliedId !== null) {
        const alreadyExists = latestAttackResults.some(item =>
            String(item.alert_id ?? item.id ?? "") === String(suppliedId)
        );
        if (alreadyExists) return;
    }

    alertSequence++;
    latestAttackResults.push({
        ...result,
        _portal_alert_number: alertSequence,
        _portal_received_at: new Date().toISOString()
    });

    if (latestAttackResults.length > 200) {
        latestAttackResults = latestAttackResults.slice(-200);
    }
    renderSecurityAttackAlerts();
}

window.addEventListener("message", event => {
    const intrusionFrame = document.querySelector('iframe[title="Intrusion detection"]');
    if (!intrusionFrame || event.source !== intrusionFrame.contentWindow) return;
    
    const message = event.data;
    if (!message || typeof message !== "object") return;

    if (message.type === "BitsFlux_ATTACK_RESULT") {
        receiveAttackResult(message.result);
        return;
    }
    
    if (message.type === "BitsFlux_ATTACK_RESULTS" && Array.isArray(message.results)) {
        message.results.forEach(receiveAttackResult);
    }

    // Check for unknown devices message from the monitoring iframe
    if (message.type === "UNKNOWN_DEVICES" && Array.isArray(message.devices)) {
        renderUnknownDevices(message.devices);
    }
});

clearAttackAlertsButton.addEventListener("click", () => {
    latestAttackResults = [];
    renderSecurityAttackAlerts();
});

// --- UNKNOWN DEVICES ---
const unknownDevicesContainer = document.getElementById("unknownDevices");
const unknownDeviceCount = document.getElementById("unknownDeviceCount");

async function loadUnknownDevices() {
    try {
        const response = await fetch("/api/devices/unknown", {
            credentials: "same-origin",
            cache: "no-store"
        });

        if (response.status === 401) {
            unknownDevicesContainer.textContent = "Your login session has expired.";
            unknownDeviceCount.textContent = "0";
            return;
        }

        if (!response.ok) throw new Error(`Device request failed: HTTP ${response.status}`);

        const devices = await response.json();
        if (!Array.isArray(devices)) throw new Error("Unexpected devices API response.");

        renderUnknownDevices(devices);
    } catch (error) {
        console.error("Unable to load unknown devices:", error);
        unknownDevicesContainer.textContent = "Could not load unknown devices. Check the server.";
        unknownDeviceCount.textContent = "0";
    }
}

async function performDeviceAction(deviceId, actionType, button, statusText) {
    if (actionType === "block" && !confirm("Are you sure you want to block this device?")) return;

    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = actionType === "approve" ? "Approving..." : "Blocking...";
    statusText.textContent = "";

    try {
        const response = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/${actionType}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({ device_name: "Monitored Device" })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || `Failed to ${actionType} device`);

        statusText.textContent = `Success: ${actionType} completed.`;
        statusText.style.color = "#35d07f";
        setTimeout(loadUnknownDevices, 1000);
    } catch (error) {
        console.error(`Device ${actionType} failed:`, error);
        statusText.textContent = `Error: ${error.message}`;
        statusText.style.color = "#ff5d6c";
        button.disabled = false;
        button.textContent = originalText;
    }
}

function renderUnknownDevices(devices) {
    unknownDeviceCount.textContent = String(devices.length);
    
    // Update global health metric
    currentUnknownCount = devices.length;
    updateNetworkHealth();

    const fragment = document.createDocumentFragment();

    if (devices.length === 0) {
        const message = document.createElement("p");
        message.className = "muted";
        message.textContent = "No unknown devices found.";
        fragment.appendChild(message);
        unknownDevicesContainer.replaceChildren(fragment);
        return;
    }

    devices.forEach(device => {
        const card = document.createElement("article");
        card.className = "card";

        const title = document.createElement("h3");
        title.textContent = device.device_name || device.hostname || "Unknown Device";
        card.appendChild(title);

        const fields = [
            ["IP Address", device.ip_address, true],
            ["MAC Address", device.mac_address, true],
            ["Domain", device.domain, false]
        ];

        fields.forEach(([label, value, needsMask]) => {
            if (value == null || value === "") return;
            const line = document.createElement("p");
            line.className = "muted";

            if (needsMask) {
                const labelText = document.createTextNode(`${label}: `);
                const masked = document.createElement("span");
                masked.className = "sensitive-data";
                masked.title = "Hover to reveal";
                masked.textContent = String(value);
                line.append(labelText, masked);
            } else {
                line.textContent = `${label}: ${value}`;
            }
            card.appendChild(line);
        });

        const actions = document.createElement("div");
        actions.className = "security-actions";

        const approveButton = document.createElement("button");
        approveButton.className = "security-btn approve-btn";
        approveButton.textContent = "Approve";

        const blockButton = document.createElement("button");
        blockButton.className = "security-btn block-btn";
        blockButton.textContent = "Block";

        const actionMessage = document.createElement("p");
        actionMessage.className = "muted action-message";

        approveButton.addEventListener("click", () => performDeviceAction(device.id, "approve", approveButton, actionMessage));
        blockButton.addEventListener("click", () => performDeviceAction(device.id, "block", blockButton, actionMessage));

        actions.append(approveButton, blockButton);
        card.append(actions, actionMessage);
        fragment.appendChild(card);
    });

    unknownDevicesContainer.replaceChildren(fragment);
}

// --- NETWORK CONFIG & DISCOVERY ---
const gatewayInput = document.getElementById("gatewayInput");
const subnetInput = document.getElementById("subnetInput");
const scanBtn = document.getElementById("scanBtn");
const scanStatus = document.getElementById("scanStatus");

function setStatus(message, color) {
    scanStatus.textContent = message;
    scanStatus.style.color = color || "var(--muted)";
}

async function loadNetworkConfig() {
    try {
        const response = await fetch("/api/config/network", {
            cache: "no-store",
            credentials: "same-origin"
        });
        if (!response.ok) return;
        const config = await response.json();
        if (config.gateway_ip) gatewayInput.value = config.gateway_ip;
        if (config.subnet) subnetInput.value = config.subnet;
    } catch (error) {
        console.error("loadNetworkConfig failed:", error);
    }
}

async function saveNetworkConfig() {
    const payload = {
        subnet: (subnetInput.value || "").trim(),
        gateway_ip: (gatewayInput.value || "").trim()
    };
    if (!payload.subnet && !payload.gateway_ip) return true;

    try {
        const response = await fetch("/api/config/network", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify(payload)
        });
        const body = await response.json();
        if (!response.ok) {
            setStatus("⚠ " + (body.error || "Save failed"), "var(--red)");
            return false;
        }
        if (body.gateway_ip) gatewayInput.value = body.gateway_ip;
        if (body.subnet) subnetInput.value = body.subnet;
        return true;
    } catch (error) {
        console.error("saveNetworkConfig failed:", error);
        setStatus("⚠ Network error saving settings", "var(--red)");
        return false;
    }
}

gatewayInput.addEventListener("blur", saveNetworkConfig);
subnetInput.addEventListener("blur", saveNetworkConfig);

async function runDiscovery() {
    setStatus("Saving settings...", "var(--muted)");
    const saved = await saveNetworkConfig();
    if (!saved) return;

    setStatus("Scanning subnet... Please wait.", "var(--muted)");
    scanBtn.disabled = true;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 90000);

    try {
        const response = await fetch("/api/discovery", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({ subnet: subnetInput.value.trim() }),
            signal: controller.signal
        });

        const body = await response.json();
        if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
        if (body.warning) {
            setStatus(" No devices found", "var(--red)");
            alert(body.warning);
            return;
        }

        setStatus(
            `${body.total_discovered ?? 0} device(s), ${body.new_unknowns ?? 0} new unknown. Opening dashboard...`,
            "var(--green)"
        );

        const frame = document.getElementById("monitorFrame");
        if (frame) frame.src = "/dashboard?_=" + Date.now();
        
        showPage("monitoring");
    } catch (error) {
        if (error.name === "AbortError") {
            setStatus(" Scan timed out after 90 seconds. Check the server.", "var(--red)");
        } else {
            setStatus(" " + error.message, "var(--red)");
        }
    } finally {
        clearTimeout(timeoutId);
        scanBtn.disabled = false;
    }
}

scanBtn.addEventListener("click", runDiscovery);

// --- NETWORK HEALTH PREDICTION ---
async function updateNetworkHealth() {
    try {
        const res = await fetch("/api/devices");
        if (!res.ok) return;
        
        const devices = await res.json();
        const knownDevices = devices.filter(d => d.is_known === 1);
        const offlineDevices = knownDevices.filter(d => d.status === "Offline");

        let score = 100;
        let reasons = [];

        // 1. Security Penalty (Attacks)
        if (currentAttackCount > 0) {
            const penalty = Math.min(currentAttackCount * 10, 40);
            score -= penalty;
            reasons.push(`${currentAttackCount} active attacks (-${penalty}%)`);
        }

        // 2. Rogue Device Penalty (Unknowns)
        if (currentUnknownCount > 0) {
            const penalty = Math.min(currentUnknownCount * 5, 30);
            score -= penalty;
            reasons.push(`${currentUnknownCount} unknown devices (-${penalty}%)`);
        }

        // 3. Reliability Penalty (Offline known devices)
        if (offlineDevices.length > 0) {
            const penalty = Math.min(offlineDevices.length * 5, 20);
            score -= penalty;
            reasons.push(`${offlineDevices.length} known devices offline (-${penalty}%)`);
        }

        score = Math.max(0, score);

        const scoreText = document.getElementById("healthScore");
        const bar = document.getElementById("healthBar");
        const reasonText = document.getElementById("healthReason");

        if (scoreText) {
            scoreText.textContent = `${score}%`;
            bar.style.width = `${score}%`;

            if (score >= 80) {
                scoreText.style.color = "var(--green)";
                bar.style.backgroundColor = "var(--green)";
            } else if (score >= 50) {
                scoreText.style.color = "#ffc857";
                bar.style.backgroundColor = "#ffc857";
            } else {
                scoreText.style.color = "var(--red)";
                bar.style.backgroundColor = "var(--red)";
            }

            reasonText.textContent = reasons.length > 0 
                ? `Risk factors: ${reasons.join(", ")}.` 
                : "All systems secure. No threats detected.";
        }
    } catch (err) {
        console.error("Failed to calculate network health:", err);
    }
}

// --- INITIALIZATION ---
renderSecurityAttackAlerts();
loadNetworkConfig();
loadUnknownDevices();
updateNetworkHealth();

setInterval(loadUnknownDevices, 5000);
setInterval(updateNetworkHealth, 10000);