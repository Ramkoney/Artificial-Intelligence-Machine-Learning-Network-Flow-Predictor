const REFRESH_MS = 5000;

const grid       = document.getElementById("deviceGrid");
const lastUpdate = document.getElementById("lastUpdate");

function escapeHtml(v) {
    if (v === null || v === undefined) return "";
    return String(v)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function renderCard(device, metric) {
    const status = (metric && metric.status) || device.status || "Unknown";
    const statusClass = status.toLowerCase();

    const unknownBadge = device.is_known === 0 ? `<span class="badge new">UNKNOWN</span>` : "";
    const blockedBadge = device.is_blocked === 1 ? `<span class="badge blocked">BLOCKED</span>` : "";

    let actions = "";
    
    // Note: We pass the IP and MAC to the onclick handlers because
    // unsaved devices will have a null ID, so the backend needs the details.
    const ip = device.ip_address || "";
    const mac = device.mac_address || "";
    const safeId = device.id || "null";

    if (device.is_blocked === 1) {
        actions = `<button class="btn-unblock" onclick="unblockDevice(${safeId})">Unblock</button>
                   <button class="btn-delete" onclick="deleteDevice(${safeId})">Delete</button>`;
    } else if (device.is_known === 0) {
        actions = `<button class="btn-approve" onclick="approveDevice(${safeId}, '${ip}', '${mac}')">Approve</button>
                   <button class="btn-block" onclick="blockDevice(${safeId}, '${ip}')">Block</button>
                   <button class="btn-delete" onclick="deleteDevice(${safeId})">Delete</button>`;
    } else {
        actions = `<button class="btn-edit" onclick="editDevice(${safeId})">Edit</button>
                   <button class="btn-delete" onclick="deleteDevice(${safeId})">Delete</button>`;
    }

    const displayMetric = (val, unit = "") => {
        if (val === null || val === undefined) return "—";
        return val + unit;
    };

    return `
        <div class="card ${device.is_known === 0 ? "unknown" : ""} ${device.is_blocked === 1 ? "blocked" : ""}">
            <div class="device-header">
                <div>
                    <h3>${escapeHtml(device.device_name || "Unknown Device")}</h3>
                    <div class="ip sensitive-data" title="Hover to reveal">${escapeHtml(ip)}</div>
                </div>
                <div class="badges">
                    <span class="status ${statusClass}">${escapeHtml(status)}</span>
                    ${unknownBadge}
                    ${blockedBadge}
                </div>
            </div>

            <div class="metrics">
                <div><span>MAC</span><strong class="sensitive-data">${escapeHtml(mac || "—")}</strong></div>
                <div><span>Domain</span><strong>${escapeHtml(device.domain || "unknown.local")}</strong></div>
                
                <div><span>Sent</span><strong>${displayMetric(metric?.packets_sent)}</strong></div>
                <div><span>Recv</span><strong>${displayMetric(metric?.packets_received)}</strong></div>
                <div><span>Loss</span><strong>${displayMetric(metric?.packet_loss, "%")}</strong></div>
                <div><span>Latency</span><strong>${displayMetric(metric?.latency_ms, " ms")}</strong></div>
                <div><span>Jitter</span><strong>${displayMetric(metric?.jitter_ms, " ms")}</strong></div>
            </div>

            <div class="device-actions">
                ${actions}
            </div>
        </div>
    `;
}

function renderGrid(devices, metricMap) {
    if (!devices.length) {
        grid.innerHTML = `<div class="card"><h3>No devices yet</h3>
                          <p>Waiting for discovery…</p></div>`;
        return;
    }

    const order = { unknown: 0, blocked: 1, offline: 2, online: 3 };
    devices.sort((a, b) => {
        const sa = (metricMap[a.id]?.status || a.status || "Unknown").toLowerCase();
        const sb = (metricMap[b.id]?.status || b.status || "Unknown").toLowerCase();
        return (order[sa] ?? 4) - (order[sb] ?? 4);
    });

    grid.innerHTML = devices
        .map(d => renderCard(d, metricMap[d.id]))
        .join("");
}

async function logoutUser() {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.href = "/login";
}

async function loadMonitor() {
    try {
        const [devRes, metRes] = await Promise.all([
            fetch("/api/devices"), // Fetch ALL devices
            fetch("/api/metrics/latest")
        ]);

        if (!devRes.ok || !metRes.ok) throw new Error("fetch failed");

        const devices = await devRes.json();
        const metrics = await metRes.json();

        const metricMap = {};
        metrics.forEach(metric => {
            if (metric.device_id !== undefined) {
                metricMap[metric.device_id] = metric;
            }
        });

        renderGrid(devices, metricMap);

        lastUpdate.textContent = "Updated " + new Date().toLocaleTimeString();
    } catch (err) {
        console.error("Monitor load failed:", err);
        lastUpdate.textContent = "⚠ Update failed";
    }
}

async function runDiscovery() {
    const subnet = prompt("Subnet to scan:", "192.168.23.0/24");
    if (subnet === null) return;

    try {
        const res = await fetch("/api/discovery", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ subnet: subnet.trim() }),
        });
        const body = await res.json();
        if (!res.ok) throw new Error(body.error || "discovery failed");
        
        alert(`Discovery complete: ${body.total_discovered} device(s), ` +
              `${body.new_unknowns} new unknown(s).`);

        // Send unknown devices to the parent dashboard (Security Info tab)
        if (window.parent && body.devices) {
            const unknowns = body.devices.filter(d => d.is_known === 0);
            window.parent.postMessage({
                type: "UNKNOWN_DEVICES",
                devices: unknowns
            }, "*");
        }

        await loadMonitor();
    } catch (err) {
        alert("Discovery failed: " + err.message);
    }
}

async function deleteDevice(deviceId) {
    if (!deviceId) return alert("Cannot delete an unsaved device.");
    if (!confirm("Delete this device?")) return;
    try {
        const res = await fetch(`/api/devices/${deviceId}`, { method: "DELETE" });
        if (!res.ok) throw new Error((await res.json()).error);
        await loadMonitor();
    } catch (err) { alert("Delete failed: " + err.message); }
}

async function editDevice(deviceId) {
    if (!deviceId) return alert("Cannot edit an unsaved device.");
    try {
        const res = await fetch(`/api/devices/${deviceId}`);
        if (!res.ok) throw new Error("get failed");
        const device = await res.json();

        const name = prompt("Device name:", device.device_name);
        if (name === null) return;
        const ip = prompt("IP address:", device.ip_address);
        if (ip === null) return;
        const mac = prompt("MAC address:", device.mac_address || "");
        if (mac === null) return;

        const put = await fetch(`/api/devices/${deviceId}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                device_name: name.trim(),
                ip_address:  ip.trim(),
                mac_address: mac.trim(),
            }),
        });
        const body = await put.json();
        if (!put.ok) throw new Error(body.error || "update failed");
        await loadMonitor();
    } catch (err) { alert("Edit failed: " + err.message); }
}

async function approveDevice(deviceId, ip, mac) {
    const name = prompt("Approve this device. Friendly name:", "Monitored Device");
    if (name === null) return;

    try {
        if (!deviceId) {
            // Device is not in DB yet, create it
            const res = await fetch(`/api/devices`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ 
                    device_name: name.trim(),
                    ip_address: ip,
                    mac_address: mac
                }),
            });
            if (!res.ok) throw new Error((await res.json()).error);
        } else {
            // Device is already in DB, just approve it
            const res = await fetch(`/api/devices/${deviceId}/approve`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ device_name: name.trim() }),
            });
            if (!res.ok) throw new Error((await res.json()).error);
        }
        await loadMonitor();
    } catch (err) { alert("Approve failed: " + err.message); }
}

async function blockDevice(deviceId, ip) {
    if (!confirm("Block this device from the network?")) return;
    try {
        if (!deviceId) {
            // Need to save it first, then block it
            const createRes = await fetch(`/api/devices`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ 
                    device_name: "Blocked Device",
                    ip_address: ip,
                    mac_address: "00:00:00:00:00:00" // Temp MAC
                }),
            });
            const created = await createRes.json();
            if (!createRes.ok) throw new Error(created.error || "Failed to save before block");
            
            // Now block the new ID
            const blockRes = await fetch(`/api/devices/${created.id}/block`, { method: "POST" });
            const blockData = await blockRes.json();
            if (!blockRes.ok) throw new Error(blockData.error || "block failed");
        } else {
            const res = await fetch(`/api/devices/${deviceId}/block`, { method: "POST" });
            const body = await res.json();
            if (!res.ok) throw new Error(body.error || "block failed");
        }
        await loadMonitor();
    } catch (err) { alert("Block failed: " + err.message); }
}

async function unblockDevice(deviceId) {
    try {
        const res = await fetch(`/api/devices/${deviceId}/unblock`, { method: "POST" });
        const body = await res.json();
        if (!res.ok) throw new Error(body.error || "unblock failed");
        await loadMonitor();
    } catch (err) { alert("Unblock failed: " + err.message); }
}

loadMonitor();
setInterval(loadMonitor, REFRESH_MS);