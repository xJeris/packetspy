// === DOM References ===
const tbody = document.getElementById("packet-tbody");
const ifaceSelect = document.getElementById("iface-select");
const profileSelect = document.getElementById("profile-select");
const btnStart = document.getElementById("btn-start");
const btnStop = document.getElementById("btn-stop");
const btnSave = document.getElementById("btn-save");
const btnLoad = document.getElementById("btn-load");
const pcapFileInput = document.getElementById("pcap-file-input");
const statusBadge = document.getElementById("status-badge");
const packetCount = document.getElementById("packet-count");
const autoScrollCheck = document.getElementById("auto-scroll");
const autoClearCheck = document.getElementById("auto-clear");
const detailViewModalRadio = document.getElementById("detail-view-modal");
const detailViewPanelRadio = document.getElementById("detail-view-panel");
const btnClear = document.getElementById("btn-clear");
const btnShutdown = document.getElementById("btn-shutdown");
const btnSettings = document.getElementById("btn-settings");
const settingsModal = document.getElementById("settings-modal");
const modalClose = document.getElementById("modal-close");
const tableContainer = document.querySelector("#tab-all-traffic .table-container");
const sidePanel = document.getElementById("side-panel");
const sidePanelClose = document.getElementById("side-panel-close");
const loadProfileModal = document.getElementById("load-profile-modal");
const loadProfileClose = document.getElementById("load-profile-close");
const loadProfileSelect = document.getElementById("load-profile-select");
const loadConfirm = document.getElementById("load-confirm");
const loadFilenameEl = document.getElementById("load-filename");

const MAX_ROWS = 1000;
let evtSource = null;
let count = 0;
let activeTab = "all-traffic";
let tabIntervals = {};
let detailViewMode = "modal";
let selectedPktNum = null;
let pendingLoadFile = null;

// === Utilities ===

function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDuration(seconds) {
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function formatAddr(ip, mac, port) {
    const host = ip || mac || "??";
    return port ? `${host}:${port}` : host;
}

function makePacketRow(pkt) {
    const row = document.createElement("tr");
    row.className = `proto-${pkt.protocol.toLowerCase()}`;
    const time = new Date(pkt.timestamp * 1000).toLocaleTimeString();
    const src = formatAddr(pkt.src_ip, pkt.src_mac, pkt.src_port);
    const dst = formatAddr(pkt.dst_ip, pkt.dst_mac, pkt.dst_port);
    row.innerHTML =
        `<td>${pkt.num}</td>` +
        `<td>${time}</td>` +
        `<td>${src}</td>` +
        `<td>${dst}</td>` +
        `<td>${pkt.protocol}</td>` +
        `<td>${pkt.length}</td>` +
        `<td>${pkt.process || ""}</td>` +
        `<td>${escapeHtml(pkt.info)}</td>`;
    row.addEventListener("click", () => showPacketDetail(pkt.num));
    return row;
}

function makePacketRowNoProc(pkt) {
    const row = document.createElement("tr");
    row.className = `proto-${pkt.protocol.toLowerCase()}`;
    const time = new Date(pkt.timestamp * 1000).toLocaleTimeString();
    const src = formatAddr(pkt.src_ip, pkt.src_mac, pkt.src_port);
    const dst = formatAddr(pkt.dst_ip, pkt.dst_mac, pkt.dst_port);
    row.innerHTML =
        `<td>${pkt.num}</td>` +
        `<td>${time}</td>` +
        `<td>${src}</td>` +
        `<td>${dst}</td>` +
        `<td>${pkt.protocol}</td>` +
        `<td>${pkt.length}</td>` +
        `<td>${escapeHtml(pkt.info)}</td>`;
    row.addEventListener("click", () => showPacketDetail(pkt.num));
    return row;
}

// === Settings ===

async function loadSettings() {
    try {
        const res = await fetch("/api/settings");
        const s = await res.json();
        autoScrollCheck.checked = s.autoScroll !== false;
        autoClearCheck.checked = s.autoClear === true;
        detailViewMode = s.detailView || "modal";
        if (detailViewMode === "panel") {
            detailViewPanelRadio.checked = true;
        } else {
            detailViewModalRadio.checked = true;
        }
    } catch (err) {
        console.error("Failed to load settings:", err);
    }
}

function saveSettings() {
    const viewMode = detailViewPanelRadio.checked ? "panel" : "modal";
    detailViewMode = viewMode;

    fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            autoScroll: autoScrollCheck.checked,
            autoClear: autoClearCheck.checked,
            detailView: viewMode,
        }),
    }).catch((err) => console.error("Failed to save settings:", err));

    // Close the other view when switching modes
    if (viewMode === "modal") {
        closeSidePanel();
    } else {
        pktDetailModal.style.display = "none";
    }
}

autoScrollCheck.addEventListener("change", saveSettings);
autoClearCheck.addEventListener("change", saveSettings);
detailViewModalRadio.addEventListener("change", saveSettings);
detailViewPanelRadio.addEventListener("change", saveSettings);

// Settings modal
btnSettings.addEventListener("click", () => {
    settingsModal.style.display = "flex";
});
modalClose.addEventListener("click", () => {
    settingsModal.style.display = "none";
});
settingsModal.addEventListener("click", (e) => {
    if (e.target === settingsModal) settingsModal.style.display = "none";
});

// === Tab Switching ===

document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
        if (tab.dataset.tab === activeTab) return;

        // Deactivate old tab
        document.querySelector(".tab.active").classList.remove("active");
        document.querySelector(".tab-content.active").classList.remove("active");
        stopTabPolling(activeTab);

        // Activate new tab
        activeTab = tab.dataset.tab;
        tab.classList.add("active");
        document.getElementById(`tab-${activeTab}`).classList.add("active");
        startTabPolling(activeTab);
    });
});

function startTabPolling(tabName) {
    stopTabPolling(tabName);
    if (tabName === "by-process") {
        refreshProcessList();
        tabIntervals[tabName] = setInterval(() => {
            refreshProcessList();
            if (selectedProcess) refreshSelectedProcessPackets();
        }, 2000);
    } else if (tabName === "streams") {
        refreshStreams();
        tabIntervals[tabName] = setInterval(refreshStreams, 3000);
    } else if (tabName === "dashboard") {
        refreshDashboard();
        tabIntervals[tabName] = setInterval(refreshDashboard, 2000);
    }
}

function stopTabPolling(tabName) {
    if (tabIntervals[tabName]) {
        clearInterval(tabIntervals[tabName]);
        delete tabIntervals[tabName];
    }
}

// === All Traffic (Tab 1) ===

function isNearBottom(container) {
    return container.scrollTop + container.clientHeight >= container.scrollHeight - 20;
}

function addPacketRow(pkt) {
    const wasAtBottom = isNearBottom(tableContainer);
    const row = makePacketRow(pkt);
    tbody.appendChild(row);
    while (tbody.children.length > MAX_ROWS) {
        tbody.removeChild(tbody.firstChild);
    }
    if (autoScrollCheck.checked && wasAtBottom) {
        tableContainer.scrollTop = tableContainer.scrollHeight;
    }
    count++;
    packetCount.textContent = `${count} packets`;
}

function clearPackets() {
    tbody.innerHTML = "";
    count = 0;
    packetCount.textContent = "0 packets";
    closeSidePanel();
}

function connectSSE() {
    if (evtSource) evtSource.close();
    evtSource = new EventSource("/api/stream");
    evtSource.onmessage = (event) => {
        const pkt = JSON.parse(event.data);
        addPacketRow(pkt);
    };
    evtSource.onerror = () => {
        console.warn("SSE connection lost, will auto-reconnect...");
    };
}

function disconnectSSE() {
    if (evtSource) {
        evtSource.close();
        evtSource = null;
    }
}

// === By Process (Tab 2) ===

let selectedProcess = null;

async function refreshProcessList() {
    try {
        const res = await fetch("/api/stats");
        const stats = await res.json();
        const list = document.getElementById("process-list");

        if (!stats.by_process || stats.by_process.length === 0) {
            list.innerHTML = '<div class="sidebar-empty">No process data yet</div>';
            return;
        }

        const items = stats.by_process;
        list.innerHTML = "";
        items.forEach((proc) => {
            const div = document.createElement("div");
            div.className = "process-item" + (proc.name === selectedProcess ? " active" : "");
            div.innerHTML =
                `<span class="process-item-name">${proc.name}</span>` +
                `<span class="process-item-count">${formatBytes(proc.bytes)}</span>`;
            div.addEventListener("click", () => selectProcess(proc.name));
            list.appendChild(div);
        });
    } catch (err) {
        console.error("Process list error:", err);
    }
}

async function selectProcess(name) {
    selectedProcess = name;
    // Update sidebar active state
    document.querySelectorAll(".process-item").forEach((el) => {
        el.classList.toggle("active", el.querySelector(".process-item-name").textContent === name);
    });
    await refreshSelectedProcessPackets();
}

async function refreshSelectedProcessPackets() {
    if (!selectedProcess) return;
    try {
        const res = await fetch(`/api/packets/by_process?process=${encodeURIComponent(selectedProcess)}`);
        const packets = await res.json();
        const ptbody = document.getElementById("process-packet-tbody");
        const container = ptbody.closest(".table-container");
        const wasAtBottom = container && isNearBottom(container);

        ptbody.innerHTML = "";
        packets.forEach((pkt) => {
            if (pkt) ptbody.appendChild(makePacketRowNoProc(pkt));
        });

        if (container && autoScrollCheck.checked && wasAtBottom) {
            container.scrollTop = container.scrollHeight;
        }
    } catch (err) {
        console.error("Process packets error:", err);
    }
}

// === Streams (Tab 3) ===

const streamListView = document.getElementById("stream-list-view");
const streamDetailView = document.getElementById("stream-detail-view");
const streamSort = document.getElementById("stream-sort");
const btnFollowStream = document.getElementById("btn-follow-stream");
const streamPacketsView = document.getElementById("stream-packets-view");
const streamConversationView = document.getElementById("stream-conversation-view");
const conversationBody = document.getElementById("conversation-body");
const convModeHex = document.getElementById("conv-mode-hex");
const convModeText = document.getElementById("conv-mode-text");
const btnFollowBack = document.getElementById("btn-follow-back");
const conversationLabel = document.getElementById("conversation-label");

let currentStreamId = null;
let convMode = "hex";
let conversationData = null;

streamSort.addEventListener("change", refreshStreams);

async function refreshStreams() {
    try {
        const sort = streamSort.value;
        const res = await fetch(`/api/streams?sort=${sort}&limit=100`);
        const streams = await res.json();
        const stbody = document.getElementById("stream-tbody");
        const streamCount = document.getElementById("stream-count");

        streamCount.textContent = `${streams.length} streams`;
        stbody.innerHTML = "";

        streams.forEach((s) => {
            const row = document.createElement("tr");
            const stateClass = `stream-state-${s.state.toLowerCase()}`;
            const protoClass = `proto-${(s.protocol || "tcp").toLowerCase()}`;
            row.innerHTML =
                `<td>${s.stream_id}</td>` +
                `<td class="${protoClass}">${s.protocol || "TCP"}</td>` +
                `<td>${s.src}</td>` +
                `<td>${s.dst}</td>` +
                `<td>${s.packet_count}</td>` +
                `<td>${formatBytes(s.total_bytes)}</td>` +
                `<td>${s.duration}s</td>` +
                `<td class="${stateClass}">${s.state}</td>` +
                `<td>${s.process || ""}</td>`;
            row.addEventListener("click", () => showStreamDetail(s));
            stbody.appendChild(row);
        });
    } catch (err) {
        console.error("Streams error:", err);
    }
}

async function showStreamDetail(stream) {
    currentStreamId = stream.stream_id;
    conversationData = null;

    streamListView.style.display = "none";
    streamDetailView.style.display = "flex";
    streamDetailView.style.flexDirection = "column";
    streamDetailView.style.flex = "1";

    // Reset to packets view
    streamPacketsView.style.display = "";
    streamConversationView.style.display = "none";
    btnFollowStream.style.display = "";

    document.getElementById("stream-detail-title").textContent =
        `${stream.protocol || "TCP"} Stream #${stream.stream_id}: ${stream.src} \u2194 ${stream.dst}`;

    try {
        const res = await fetch(`/api/streams/${stream.stream_id}/packets`);
        const packets = await res.json();
        const dtbody = document.getElementById("stream-detail-tbody");
        dtbody.innerHTML = "";
        packets.forEach((pkt) => {
            if (pkt) dtbody.appendChild(makePacketRow(pkt));
        });
    } catch (err) {
        console.error("Stream detail error:", err);
    }
}

document.getElementById("stream-back").addEventListener("click", () => {
    streamConversationView.style.display = "none";
    streamPacketsView.style.display = "";
    btnFollowStream.style.display = "";
    conversationData = null;
    currentStreamId = null;

    streamDetailView.style.display = "none";
    streamListView.style.display = "flex";
    streamListView.style.flexDirection = "column";
    streamListView.style.flex = "1";
});

// Follow Stream button
btnFollowStream.addEventListener("click", async () => {
    if (!currentStreamId) return;
    try {
        const res = await fetch(`/api/streams/${currentStreamId}/conversation`);
        conversationData = await res.json();
        streamPacketsView.style.display = "none";
        streamConversationView.style.display = "flex";
        btnFollowStream.style.display = "none";
        renderConversation(conversationData, convMode);
    } catch (err) {
        console.error("Conversation error:", err);
    }
});

// Show Packets button (back from conversation)
btnFollowBack.addEventListener("click", () => {
    streamConversationView.style.display = "none";
    streamPacketsView.style.display = "";
    btnFollowStream.style.display = "";
    conversationData = null;
});

// Hex/Text mode toggles
convModeHex.addEventListener("click", () => {
    convMode = "hex";
    convModeHex.classList.add("active");
    convModeText.classList.remove("active");
    if (conversationData) renderConversation(conversationData, convMode);
});

convModeText.addEventListener("click", () => {
    convMode = "text";
    convModeText.classList.add("active");
    convModeHex.classList.remove("active");
    if (conversationData) renderConversation(conversationData, convMode);
});

function renderConversation(packets, mode) {
    conversationBody.innerHTML = "";

    let clientLabel = "Client";
    let serverLabel = "Server";
    if (packets.length > 0) {
        const first = packets.find(p => p.direction === "client") || packets[0];
        clientLabel = `${first.src_ip}:${first.src_port}`;
        serverLabel = `${first.dst_ip}:${first.dst_port}`;
    }

    conversationLabel.textContent = `${clientLabel} \u2194 ${serverLabel}`;

    const dataPackets = packets.filter(p => p.has_payload);

    if (dataPackets.length === 0) {
        conversationBody.innerHTML =
            '<div class="conv-empty">No payload data in this stream</div>';
        return;
    }

    dataPackets.forEach(pkt => {
        const block = document.createElement("div");
        block.className = `conv-block conv-${pkt.direction}`;

        const ts = pkt.timestamp
            ? new Date(pkt.timestamp * 1000).toLocaleTimeString()
            : "?";

        const dirLabel = pkt.direction === "client"
            ? `${clientLabel} \u2192 ${serverLabel}`
            : `${serverLabel} \u2192 ${clientLabel}`;

        let payloadContent;
        if (mode === "hex") {
            payloadContent = formatConvHexdump(pkt.payload_hex);
        } else {
            payloadContent = escapeHtml(pkt.payload_text);
        }

        block.innerHTML =
            `<div class="conv-block-header">` +
            `<span class="conv-dir-label">${escapeHtml(dirLabel)}</span>` +
            `<span class="conv-ts">${ts}</span>` +
            `<span class="conv-len">${pkt.payload_len} bytes</span>` +
            `</div>` +
            `<pre class="conv-payload">${payloadContent}</pre>`;

        conversationBody.appendChild(block);
    });
}

function formatConvHexdump(hexStr) {
    const bytes = [];
    for (let i = 0; i < hexStr.length; i += 2) {
        bytes.push(parseInt(hexStr.substring(i, i + 2), 16));
    }
    const width = 16;
    const lines = [];
    for (let offset = 0; offset < bytes.length; offset += width) {
        const chunk = bytes.slice(offset, offset + width);
        const hexPart1 = chunk.slice(0, 8).map(b => b.toString(16).padStart(2, "0")).join(" ");
        const hexPart2 = chunk.slice(8).map(b => b.toString(16).padStart(2, "0")).join(" ");
        const hexPart = hexPart2.length > 0 ? `${hexPart1}  ${hexPart2}` : hexPart1;
        const asciiPart = chunk.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : ".").join("");
        lines.push(`${offset.toString(16).padStart(4, "0")}   ${hexPart.padEnd(49)}  ${escapeHtml(asciiPart)}`);
    }
    return lines.join("\n");
}

// === Dashboard (Tab 4) ===

async function refreshDashboard() {
    try {
        const res = await fetch("/api/stats");
        const stats = await res.json();

        // Summary
        document.getElementById("dash-total-packets").textContent = stats.total_packets.toLocaleString();
        document.getElementById("dash-total-bytes").textContent = formatBytes(stats.total_bytes);
        document.getElementById("dash-rate").textContent = formatBytes(stats.bytes_per_second) + "/s";
        document.getElementById("dash-elapsed").textContent = formatDuration(stats.elapsed_seconds);

        // Protocols
        renderProtocolBars(stats.by_protocol);

        // Processes
        renderProcessBars(stats.by_process);

        // Top talkers
        renderTalkers(stats.top_talkers);
    } catch (err) {
        console.error("Dashboard error:", err);
    }
}

function renderProtocolBars(byProto) {
    const container = document.getElementById("stats-protocols");
    const entries = Object.entries(byProto).sort((a, b) => b[1].bytes - a[1].bytes);
    const maxBytes = entries.length > 0 ? entries[0][1].bytes : 1;

    container.innerHTML = "";
    entries.forEach(([proto, data]) => {
        const pct = (data.bytes / maxBytes) * 100;
        const fillClass = proto === "TCP" ? "bar-fill-tcp" : proto === "UDP" ? "bar-fill-udp" : "bar-fill-default";
        container.innerHTML +=
            `<div class="bar-row">` +
            `<span class="bar-label">${proto}</span>` +
            `<div class="bar-track"><div class="bar-fill ${fillClass}" style="width:${pct}%"></div></div>` +
            `<span class="bar-value">${formatBytes(data.bytes)}</span>` +
            `</div>`;
    });

    if (entries.length === 0) {
        container.innerHTML = '<div class="sidebar-empty">No data yet</div>';
    }
}

function renderProcessBars(byProcess) {
    const container = document.getElementById("stats-processes");
    const maxBytes = byProcess.length > 0 ? byProcess[0].bytes : 1;

    container.innerHTML = "";
    byProcess.slice(0, 10).forEach((proc) => {
        const pct = (proc.bytes / maxBytes) * 100;
        container.innerHTML +=
            `<div class="bar-row">` +
            `<span class="bar-label">${proc.name}</span>` +
            `<div class="bar-track"><div class="bar-fill bar-fill-process" style="width:${pct}%"></div></div>` +
            `<span class="bar-value">${formatBytes(proc.bytes)}</span>` +
            `</div>`;
    });

    if (byProcess.length === 0) {
        container.innerHTML = '<div class="sidebar-empty">No data yet</div>';
    }
}

function renderTalkers(talkers) {
    const container = document.getElementById("stats-talkers");
    container.innerHTML = "";

    talkers.forEach((t) => {
        container.innerHTML +=
            `<div class="talker-row">` +
            `<span class="talker-ip">${t.ip}</span>` +
            `<span class="talker-bytes">${formatBytes(t.bytes)}</span>` +
            `<span class="talker-dir">\u2191${t.as_src} \u2193${t.as_dst}</span>` +
            `</div>`;
    });

    if (talkers.length === 0) {
        container.innerHTML = '<div class="sidebar-empty">No data yet</div>';
    }
}

// === Packet Detail (Modal + Side Panel) ===

const pktDetailModal = document.getElementById("packet-detail-modal");
const pktDetailClose = document.getElementById("pkt-detail-close");

pktDetailClose.addEventListener("click", () => {
    pktDetailModal.style.display = "none";
});
pktDetailModal.addEventListener("click", (e) => {
    if (e.target === pktDetailModal) pktDetailModal.style.display = "none";
});

sidePanelClose.addEventListener("click", closeSidePanel);

function openSidePanel() {
    sidePanel.style.display = "flex";
}

function closeSidePanel() {
    sidePanel.style.display = "none";
    clearPacketRowHighlight();
    selectedPktNum = null;
}

// Side panel resize drag
(function() {
    const resizeHandle = document.getElementById("side-panel-resize");
    if (!resizeHandle) return;
    let dragging = false;
    let startX, startWidth;

    resizeHandle.addEventListener("mousedown", (e) => {
        dragging = true;
        startX = e.clientX;
        startWidth = sidePanel.offsetWidth;
        resizeHandle.classList.add("dragging");
        document.body.style.cursor = "col-resize";
        document.body.style.userSelect = "none";
        e.preventDefault();
    });

    document.addEventListener("mousemove", (e) => {
        if (!dragging) return;
        // Dragging left edge: moving mouse left = panel gets wider
        const delta = startX - e.clientX;
        const newWidth = Math.max(280, Math.min(window.innerWidth * 0.8, startWidth + delta));
        sidePanel.style.width = newWidth + "px";
    });

    document.addEventListener("mouseup", () => {
        if (!dragging) return;
        dragging = false;
        resizeHandle.classList.remove("dragging");
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
    });
})();

function highlightPacketRow(pktNum) {
    clearPacketRowHighlight();
    selectedPktNum = pktNum;
    const tbodies = ["packet-tbody", "process-packet-tbody", "stream-detail-tbody"];
    for (const tbodyId of tbodies) {
        const tb = document.getElementById(tbodyId);
        if (!tb) continue;
        for (const row of tb.children) {
            if (row.cells[0] && row.cells[0].textContent === String(pktNum)) {
                row.classList.add("pkt-selected");
            }
        }
    }
}

function clearPacketRowHighlight() {
    document.querySelectorAll("tr.pkt-selected").forEach(r => r.classList.remove("pkt-selected"));
}

function renderPacketDetail(detail, prefix) {
    // Title
    document.getElementById(`${prefix}-title`).textContent = `Packet #${detail.num}`;

    // Summary
    const summary = document.getElementById(`${prefix}-summary`);
    const time = detail.timestamp
        ? new Date(detail.timestamp * 1000).toLocaleTimeString()
        : "?";

    let dirHtml = "";
    if (detail.direction && detail.direction.label) {
        dirHtml = `<div class="pkt-summary-row">` +
            `<span class="pkt-summary-label">Direction</span>` +
            `<span class="pkt-direction">${detail.direction.label}</span>` +
            `</div>`;
    }

    let procHtml = "";
    if (detail.process) {
        const pidStr = detail.pid ? ` (PID ${detail.pid})` : "";
        procHtml = `<div class="pkt-summary-row">` +
            `<span class="pkt-summary-label">Process</span>` +
            `<span class="pkt-summary-value">${detail.process}${pidStr}</span>` +
            `</div>`;
    }

    summary.innerHTML =
        dirHtml +
        `<div class="pkt-summary-row">` +
        `<span class="pkt-summary-label">Time</span>` +
        `<span class="pkt-summary-value">${time}</span>` +
        `</div>` +
        `<div class="pkt-summary-row">` +
        `<span class="pkt-summary-label">Length</span>` +
        `<span class="pkt-summary-value">${detail.length} bytes</span>` +
        `</div>` +
        procHtml;

    // Layers
    const layersDiv = document.getElementById(`${prefix}-layers`);
    layersDiv.innerHTML = "";
    detail.layers.forEach((layer) => {
        const layerEl = document.createElement("div");
        layerEl.className = "pkt-layer";

        const header = document.createElement("div");
        header.className = "pkt-layer-header";
        header.innerHTML = `<span class="pkt-layer-toggle">\u25BC</span> ${layer.name}`;

        const fields = document.createElement("div");
        fields.className = "pkt-layer-fields";
        layer.fields.forEach((f) => {
            const fieldEl = document.createElement("div");
            fieldEl.className = "pkt-field";
            fieldEl.dataset.field = f.name;
            fieldEl.innerHTML =
                `<span class="pkt-field-name">${escapeHtml(String(f.name))}</span>` +
                `<span class="pkt-field-value">${escapeHtml(String(f.value))}</span>`;
            fields.appendChild(fieldEl);
        });

        header.addEventListener("click", () => {
            const visible = fields.style.display !== "none";
            fields.style.display = visible ? "none" : "block";
            header.querySelector(".pkt-layer-toggle").textContent = visible ? "\u25B6" : "\u25BC";
        });

        layerEl.appendChild(header);
        layerEl.appendChild(fields);
        layersDiv.appendChild(layerEl);
    });

    // Addon sections (protocol parsers)
    let byteRegions = null;
    if (detail.addons) {
        detail.addons.forEach(addon => {
            renderAddonSection(layersDiv, addon);
            if (addon.data && addon.data.byte_regions) {
                byteRegions = addon.data.byte_regions;
            }
        });
    }

    // Payload
    const payloadDiv = document.getElementById(`${prefix}-payload`);
    if (detail.payload && detail.payload.hexdump) {
        if (byteRegions) {
            payloadDiv.innerHTML =
                `<div class="pkt-payload-title">Payload (${detail.payload.length} bytes)</div>` +
                `<pre class="pkt-hexdump">${formatAnnotatedHexdump(detail.payload.hexdump, byteRegions)}</pre>`;
        } else {
            payloadDiv.innerHTML =
                `<div class="pkt-payload-title">Payload (${detail.payload.length} bytes)</div>` +
                `<pre class="pkt-hexdump">${escapeHtml(detail.payload.hexdump)}</pre>`;
        }
    } else {
        payloadDiv.innerHTML =
            `<div class="pkt-payload-title" style="color:#808080;">No payload</div>`;
    }
}

async function showPacketDetail(pktNum) {
    try {
        const res = await fetch(`/api/packets/${pktNum}/detail`);
        if (!res.ok) return;
        const detail = await res.json();

        if (detailViewMode === "panel") {
            renderPacketDetail(detail, "side-panel");
            openSidePanel();
            highlightPacketRow(pktNum);
        } else {
            renderPacketDetail(detail, "pkt-detail");
            pktDetailModal.style.display = "flex";
        }
    } catch (err) {
        console.error("Packet detail error:", err);
    }
}

function renderAddonSection(container, addon) {
    if (!addon || !addon.data) return;

    const layerEl = document.createElement("div");
    layerEl.className = "pkt-layer addon-layer";

    const header = document.createElement("div");
    header.className = "pkt-layer-header addon-header";
    let headerHtml = `<span class="pkt-layer-toggle">\u25BC</span> ${escapeHtml(addon.name)}`;
    if (addon.data.flags && addon.data.flags.length) {
        addon.data.flags.forEach(flag => {
            headerHtml += ` <span class="addon-flag addon-flag-${flag}">${escapeHtml(flag)}</span>`;
        });
    }
    header.innerHTML = headerHtml;

    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";

    // Render fields from addon data
    if (addon.data.fields) {
        addon.data.fields.forEach(f => {
            const fieldEl = document.createElement("div");
            fieldEl.className = "pkt-field";
            fieldEl.innerHTML =
                `<span class="pkt-field-name">${escapeHtml(String(f.name))}</span>` +
                `<span class="pkt-field-value">${escapeHtml(String(f.value))}</span>`;
            fields.appendChild(fieldEl);
        });
    }

    // Notes summary line
    if (addon.data.notes) {
        const notesEl = document.createElement("div");
        notesEl.className = "addon-notes";
        notesEl.textContent = addon.data.notes;
        fields.appendChild(notesEl);
    }

    // Decoded payload hex dump
    if (addon.data.decoded_payload) {
        const decodedTitle = document.createElement("div");
        decodedTitle.className = "addon-decoded-title";
        decodedTitle.textContent = "Decoded Payload";
        fields.appendChild(decodedTitle);

        const decodedPre = document.createElement("pre");
        decodedPre.className = "pkt-hexdump addon-decoded-hex";
        decodedPre.innerHTML = formatConvHexdump(addon.data.decoded_payload);
        fields.appendChild(decodedPre);
    }

    header.addEventListener("click", () => {
        const visible = fields.style.display !== "none";
        fields.style.display = visible ? "none" : "block";
        header.querySelector(".pkt-layer-toggle").textContent = visible ? "\u25B6" : "\u25BC";
    });

    layerEl.appendChild(header);
    layerEl.appendChild(fields);
    container.appendChild(layerEl);
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

function formatAnnotatedHexdump(hexdumpStr, regions) {
    // Build a byte-index-to-region-type lookup
    const byteType = {};
    regions.forEach(r => {
        for (let i = r.start; i < r.end; i++) byteType[i] = r.type;
    });

    const lines = hexdumpStr.split("\n");
    const result = [];
    for (const line of lines) {
        // Parse: "0000   xx xx xx ...  ASCII"
        // Find the offset (first 4 hex chars)
        const match = line.match(/^([0-9a-f]{4})(   )(.*?)(  )(.*)$/);
        if (!match) {
            result.push(escapeHtml(line));
            continue;
        }
        const offsetStr = match[1];
        const offsetNum = parseInt(offsetStr, 16);
        const sep1 = match[2];
        const hexPart = match[3];
        const sep2 = match[4];
        const asciiPart = match[5];

        // Split hex part into individual byte tokens, preserving spacing
        // Format: "xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx"
        let annotatedHex = "";
        let annotatedAscii = "";
        let byteIdx = offsetNum;
        let i = 0;
        let asciiIdx = 0;
        while (i < hexPart.length) {
            if (hexPart[i] === " ") {
                annotatedHex += " ";
                i++;
                continue;
            }
            // Read 2-char hex byte
            if (i + 1 < hexPart.length && /[0-9a-f]/i.test(hexPart[i]) && /[0-9a-f]/i.test(hexPart[i + 1])) {
                const hexByte = hexPart.substring(i, i + 2);
                const regionType = byteType[byteIdx] || "";
                if (regionType) {
                    annotatedHex += `<span class="hex-${regionType}">${hexByte}</span>`;
                } else {
                    annotatedHex += escapeHtml(hexByte);
                }
                // Corresponding ASCII char
                if (asciiIdx < asciiPart.length) {
                    const asciiChar = escapeHtml(asciiPart[asciiIdx]);
                    if (regionType) {
                        annotatedAscii += `<span class="hex-${regionType}">${asciiChar}</span>`;
                    } else {
                        annotatedAscii += asciiChar;
                    }
                    asciiIdx++;
                }
                byteIdx++;
                i += 2;
            } else {
                annotatedHex += escapeHtml(hexPart[i]);
                i++;
            }
        }
        // Include remaining ASCII chars (shouldn't happen, but safety)
        while (asciiIdx < asciiPart.length) {
            annotatedAscii += escapeHtml(asciiPart[asciiIdx]);
            asciiIdx++;
        }

        result.push(`${escapeHtml(offsetStr)}${sep1}${annotatedHex}${sep2}${annotatedAscii}`);
    }
    return result.join("\n");
}

// === Capture Controls ===

function setRunningState(running) {
    if (running) {
        statusBadge.textContent = "Running";
        statusBadge.className = "badge badge-running";
        btnStart.disabled = true;
        btnStop.disabled = false;
        ifaceSelect.disabled = true;
        profileSelect.disabled = true;
    } else {
        statusBadge.textContent = "Stopped";
        statusBadge.className = "badge badge-stopped";
        btnStart.disabled = false;
        btnStop.disabled = true;
        ifaceSelect.disabled = false;
        profileSelect.disabled = false;
    }
}

btnStart.addEventListener("click", async () => {
    const body = {};
    if (ifaceSelect.value) body.iface = ifaceSelect.value;
    if (profileSelect.value) body.profile = profileSelect.value;

    try {
        const res = await fetch("/api/capture/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.status === "started") {
            if (autoClearCheck.checked) clearPackets();
            setRunningState(true);
            connectSSE();
            startTabPolling(activeTab);
        }
    } catch (err) {
        console.error("Start error:", err);
    }
});

btnStop.addEventListener("click", async () => {
    try {
        const res = await fetch("/api/capture/stop", { method: "POST" });
        const data = await res.json();
        if (data.status === "stopped") {
            setRunningState(false);
            disconnectSSE();
        }
    } catch (err) {
        console.error("Stop error:", err);
    }
});

btnSave.addEventListener("click", async () => {
    try {
        const res = await fetch("/api/pcap/save", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({}),
        });
        const data = await res.json();
        if (data.filename) {
            alert(`Saved: ${data.filename}`);
        } else if (data.error) {
            alert(data.error);
        }
    } catch (err) {
        console.error("Save error:", err);
    }
});

// === Load PCAP ===

btnLoad.addEventListener("click", () => { pcapFileInput.click(); });

pcapFileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;

    pendingLoadFile = file;
    loadFilenameEl.textContent = file.name;

    // Populate load profile select from existing profile options
    loadProfileSelect.innerHTML = '<option value="">No Profile</option>';
    for (const opt of profileSelect.options) {
        if (opt.value) {
            const newOpt = document.createElement("option");
            newOpt.value = opt.value;
            newOpt.textContent = opt.textContent;
            loadProfileSelect.appendChild(newOpt);
        }
    }

    loadProfileModal.style.display = "flex";
    pcapFileInput.value = "";
});

loadConfirm.addEventListener("click", async () => {
    if (!pendingLoadFile) return;

    const file = pendingLoadFile;
    const profileName = loadProfileSelect.value;
    pendingLoadFile = null;

    // Show loading state — keep modal open, disable controls
    loadConfirm.disabled = true;
    loadConfirm.textContent = "Uploading...";
    loadProfileSelect.disabled = true;
    loadProfileClose.style.display = "none";

    const formData = new FormData();
    formData.append("file", file);
    if (profileName) formData.append("profile", profileName);

    try {
        // Step 1: Upload file and get a load_id
        const res = await fetch("/api/pcap/load", { method: "POST", body: formData });
        const data = await res.json();
        if (data.error) {
            alert(data.error);
            return;
        }

        clearPackets();
        loadConfirm.textContent = "Loading...";

        // Step 2: Stream parsed packets via SSE
        const loadSource = new EventSource(`/api/pcap/load/${data.load_id}/stream`);
        loadSource.onmessage = (event) => {
            const msg = JSON.parse(event.data);
            if (msg.type === "packets") {
                const wasAtBottom = isNearBottom(tableContainer);
                const frag = document.createDocumentFragment();
                msg.packets.forEach(pkt => frag.appendChild(makePacketRow(pkt)));
                tbody.appendChild(frag);
                while (tbody.children.length > MAX_ROWS) {
                    tbody.removeChild(tbody.firstChild);
                }
                count += msg.packets.length;
                packetCount.textContent = `${count} packets`;
                if (autoScrollCheck.checked && wasAtBottom) {
                    tableContainer.scrollTop = tableContainer.scrollHeight;
                }
            } else if (msg.type === "done") {
                loadSource.close();
                statusBadge.textContent = `Loaded: ${msg.filename}`;
                statusBadge.className = "badge badge-loaded";
                resetLoadModal();
            } else if (msg.type === "error") {
                loadSource.close();
                alert(`Load error: ${msg.error}`);
                resetLoadModal();
            }
        };
        loadSource.onerror = () => {
            loadSource.close();
            alert("PCAP load stream failed");
            resetLoadModal();
        };
    } catch (err) {
        console.error("Load error:", err);
        alert("Failed to load PCAP file");
        resetLoadModal();
    }
});

function resetLoadModal() {
    loadConfirm.disabled = false;
    loadConfirm.textContent = "Load";
    loadProfileSelect.disabled = false;
    loadProfileClose.style.display = "";
    loadProfileModal.style.display = "none";
}

loadProfileClose.addEventListener("click", () => {
    loadProfileModal.style.display = "none";
    pendingLoadFile = null;
});
loadProfileModal.addEventListener("click", (e) => {
    if (e.target === loadProfileModal) {
        loadProfileModal.style.display = "none";
        pendingLoadFile = null;
    }
});

btnShutdown.addEventListener("click", async () => {
    if (!confirm("Shutdown PacketSpy? This will stop capture and close the server.")) return;
    disconnectSSE();
    Object.keys(tabIntervals).forEach(stopTabPolling);
    try {
        await fetch("/api/shutdown", { method: "POST" });
    } catch {
        // Expected — server dies before responding
    }
    document.body.innerHTML =
        '<div style="display:flex;align-items:center;justify-content:center;height:100vh;color:#808080;font-size:18px;">PacketSpy has been shut down. You can close this tab.</div>';
});

btnClear.addEventListener("click", clearPackets);

// === Init ===

async function init() {
    await loadSettings();

    try {
        const [ifaceRes, profileRes, statusRes] = await Promise.all([
            fetch("/api/interfaces"),
            fetch("/api/profiles"),
            fetch("/api/capture/status"),
        ]);

        const ifaces = await ifaceRes.json();
        ifaces.forEach((iface) => {
            const opt = document.createElement("option");
            opt.value = iface.name;
            const label = iface.ip
                ? `${iface.description || iface.name} (${iface.ip})`
                : iface.description || iface.name;
            opt.textContent = label;
            ifaceSelect.appendChild(opt);
        });

        const profiles = await profileRes.json();
        profiles.forEach((p) => {
            const opt = document.createElement("option");
            opt.value = p.filename;
            opt.textContent = p.name;
            profileSelect.appendChild(opt);
        });

        const status = await statusRes.json();
        if (status.running) {
            setRunningState(true);
            count = status.packet_count;
            packetCount.textContent = `${count} packets`;
            connectSSE();
            startTabPolling(activeTab);
        }
    } catch (err) {
        console.error("Init error:", err);
    }
}

init();
