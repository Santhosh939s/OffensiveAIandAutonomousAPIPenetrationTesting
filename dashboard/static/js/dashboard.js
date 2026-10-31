/**
 * Autonomous API Security Dashboard - Live Frontend Controller
 * Connects to Flask REST APIs and Server-Sent Events (SSE) telemetry.
 */

document.addEventListener("DOMContentLoaded", () => {
    // State
    let activeSessionId = null;
    let sseSource = null;
    let maxTurns = 8;
    let cachedTraffic = [];
    let cachedFindings = [];

    // Elements
    const navTabs = document.querySelectorAll(".nav-tab");
    const tabPanes = document.querySelectorAll(".tab-pane");
    const systemStatusLight = document.getElementById("system-status-indicator");
    const systemStatusText = document.getElementById("system-status-text");
    const brainModeLabel = document.getElementById("brain-mode-label");
    const zapStatusLabel = document.getElementById("zap-status-label");
    const currentTargetDisplay = document.getElementById("current-target-display");
    const currentSessionDisplay = document.getElementById("current-session-display");
    const assessmentBadge = document.getElementById("assessment-badge");
    const liveIndicator = document.getElementById("live-indicator");
    const cancelBtn = document.getElementById("cancel-btn");
    const findingsCountBadge = document.getElementById("findings-count-badge");

    // Form Elements
    const assessmentForm = document.getElementById("assessment-form");
    const brainModeSelect = document.getElementById("brain_mode");
    const remoteEndpointGroup = document.getElementById("remote-endpoint-group");
    const startStatusMsg = document.getElementById("start-status-msg");

    // Live Feed Elements
    const liveEventFeed = document.getElementById("live-event-feed");
    const autoScrollCheckbox = document.getElementById("auto-scroll-checkbox");
    const clearFeedBtn = document.getElementById("clear-feed-btn");
    const executionProgressBar = document.getElementById("execution-progress-bar");
    const executionStateLabel = document.getElementById("execution-state-label");
    const progressSummary = document.getElementById("progress-summary");

    // Traffic Elements
    const trafficTableBody = document.getElementById("traffic-table-body");
    const trafficDetailContainer = document.getElementById("traffic-detail-container");
    const selectedTrafficStatus = document.getElementById("selected-traffic-status");
    const refreshTrafficBtn = document.getElementById("refresh-traffic-btn");

    // Findings Elements
    const findingsList = document.getElementById("findings-list");
    const findingsStatusFilter = document.getElementById("findings-status-filter");
    const refreshFindingsBtn = document.getElementById("refresh-findings-btn");

    // Report Elements
    const reportPreview = document.getElementById("report-content-preview");
    const downloadReportBtn = document.getElementById("download-report-btn");
    const refreshReportBtn = document.getElementById("refresh-report-btn");

    // Sessions Table & Refresh
    const sessionsTableBody = document.querySelector("#sessions-table tbody");
    const refreshSessionsBtn = document.getElementById("refresh-sessions-btn");

    // --- TAB NAVIGATION ---
    navTabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const targetTab = tab.getAttribute("data-tab");
            switchTab(targetTab);
        });
    });

    function switchTab(tabName) {
        navTabs.forEach(t => {
            if (t.getAttribute("data-tab") === tabName) {
                t.classList.add("active");
            } else {
                t.classList.remove("active");
            }
        });

        tabPanes.forEach(pane => {
            if (pane.id === `tab-${tabName}`) {
                pane.classList.add("active");
            } else {
                pane.classList.remove("active");
            }
        });

        // Trigger context refreshes when entering tabs
        if (tabName === "traffic-inspector" && activeSessionId) {
            loadTraffic(activeSessionId);
        } else if (tabName === "security-findings" && activeSessionId) {
            loadFindings(activeSessionId);
        } else if (tabName === "reports" && activeSessionId) {
            loadReport(activeSessionId);
        } else if (tabName === "dashboard") {
            loadRecentSessions();
        }
    }

    // --- SYSTEM DIAGNOSTICS & STATUS ---
    async function checkSystemHealth() {
        try {
            const resp = await fetch("/api/system/status");
            if (!resp.ok) throw new Error("Health check failed");
            const data = await resp.json();

            systemStatusLight.classList.add("online");
            systemStatusText.textContent = "Engine Online";

            const zapInfo = data.zap_daemon || {};
            zapStatusLabel.textContent = `ZAP: ${zapInfo.connected ? "Connected" : "Offline"}`;
            const zapDiag = document.getElementById("diag-zap-status");
            if (zapDiag) {
                zapDiag.textContent = zapInfo.connected ? `Connected (${zapInfo.version})` : "Offline (Daemon not detected on localhost:8080)";
                zapDiag.className = zapInfo.connected ? "diag-val text-green" : "diag-val text-warning";
            }

            const diagZapUrl = document.getElementById("diag-zap-url");
            if (diagZapUrl && zapInfo.url) diagZapUrl.textContent = zapInfo.url;

            const diagAllowed = document.getElementById("diag-allowed-hosts");
            if (diagAllowed && data.default_allowed_hosts) {
                diagAllowed.textContent = data.default_allowed_hosts.join(", ");
            }

            // Low-Resource & RAM Profile
            const resProfile = data.resource_profile || {};
            const sysMem = resProfile.system_memory || {};
            const procMem = resProfile.process_memory || {};

            const diagSysRam = document.getElementById("diag-system-ram");
            if (diagSysRam && sysMem.total_ram_mb) {
                diagSysRam.textContent = `${(sysMem.total_ram_mb / 1024).toFixed(2)} GB (${sysMem.total_ram_mb} MB)`;
            }

            const diagAvailRam = document.getElementById("diag-avail-ram");
            if (diagAvailRam && sysMem.available_ram_mb) {
                diagAvailRam.textContent = `${(sysMem.available_ram_mb / 1024).toFixed(2)} GB (${sysMem.available_ram_mb} MB) [${sysMem.memory_load_pct}% load]`;
            }

            const diagProcRam = document.getElementById("diag-proc-ram");
            if (diagProcRam && procMem.working_set_mb !== undefined) {
                diagProcRam.textContent = `${procMem.working_set_mb} MB (Working Set) / Peak: ${procMem.peak_working_set_mb || procMem.working_set_mb} MB`;
            }

            const diagRecMode = document.getElementById("diag-rec-mode");
            if (diagRecMode && resProfile.recommended_mode) {
                diagRecMode.textContent = `${resProfile.recommended_mode.toUpperCase()} MODE`;
            }

            const diagRationale = document.getElementById("diag-mode-rationale");
            if (diagRationale && resProfile.recommendation_rationale) {
                diagRationale.textContent = resProfile.recommendation_rationale;
            }
        } catch (err) {
            systemStatusLight.classList.remove("online");
            systemStatusText.textContent = "Offline / Disconnected";
            zapStatusLabel.textContent = "ZAP: Offline";
        }
    }

    // Toggle Remote Endpoint Input
    brainModeSelect.addEventListener("change", () => {
        if (brainModeSelect.value === "remote") {
            remoteEndpointGroup.style.display = "block";
        } else {
            remoteEndpointGroup.style.display = "none";
        }
        brainModeLabel.textContent = `Brain: ${brainModeSelect.options[brainModeSelect.selectedIndex].text.split(" ")[0]}`;
    });

    // --- LAUNCH ASSESSMENT ---
    assessmentForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        startStatusMsg.textContent = "Initiating assessment...";
        startStatusMsg.style.color = "var(--accent-cyan)";

        const payload = {
            target_url: document.getElementById("target_url").value.trim(),
            allowed_hosts: document.getElementById("allowed_hosts").value.split(",").map(s => s.trim()).filter(Boolean),
            assessment_name: document.getElementById("assessment_name").value.trim(),
            brain_mode: brainModeSelect.value,
            remote_endpoint: document.getElementById("remote_endpoint").value.trim() || null,
            spec_source: document.getElementById("spec_source").value.trim() || null,
            max_turns: parseInt(document.getElementById("max_turns").value, 10),
            max_requests: parseInt(document.getElementById("max_requests").value, 10),
            max_model_calls: parseInt(document.getElementById("max_model_calls").value, 10),
            zap_active_scan: document.getElementById("zap_active_scan").checked,
        };

        maxTurns = payload.max_turns;

        try {
            const resp = await fetch("/api/assessments/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            const result = await resp.json();

            if (!resp.ok || !result.success) {
                startStatusMsg.textContent = `Error: ${result.error || "Failed to start"}`;
                startStatusMsg.style.color = "var(--status-red)";
                return;
            }

            activeSessionId = result.session_id;
            currentTargetDisplay.textContent = payload.target_url;
            currentSessionDisplay.textContent = activeSessionId;
            setAssessmentState("RUNNING");
            startStatusMsg.textContent = "Assessment running!";
            startStatusMsg.style.color = "var(--status-green)";

            // Clear feed and prepare live activity
            liveEventFeed.innerHTML = "";
            cancelBtn.disabled = false;
            liveIndicator.classList.remove("hidden");

            // Switch to Live Activity tab and connect stream
            switchTab("live-activity");
            connectEventStream(activeSessionId);

        } catch (err) {
            startStatusMsg.textContent = `Connection error: ${err.message}`;
            startStatusMsg.style.color = "var(--status-red)";
        }
    });

    // --- CANCEL ASSESSMENT ---
    cancelBtn.addEventListener("click", async () => {
        if (!activeSessionId) return;
        cancelBtn.disabled = true;
        cancelBtn.textContent = "Cancelling...";

        try {
            const resp = await fetch(`/api/assessments/${activeSessionId}/cancel`, { method: "POST" });
            const data = await resp.json();
            if (data.success) {
                appendEventCard({
                    event_type: "assessment_cancelled",
                    timestamp: new Date().toISOString(),
                    data: { message: "Assessment cancelled by operator." }
                });
                setAssessmentState("CANCELLED");
            }
        } catch (err) {
            console.error("Cancel failed:", err);
        } finally {
            cancelBtn.textContent = "Cancel Scan";
        }
    });

    // --- REAL-TIME SSE TELEMETRY STREAM ---
    function connectEventStream(sessionId) {
        if (sseSource) {
            sseSource.close();
            sseSource = null;
        }

        const streamUrl = `/api/stream/${sessionId}`;
        sseSource = new EventSource(streamUrl);

        sseSource.onmessage = (e) => {
            try {
                const eventObj = JSON.parse(e.data);
                handleControllerEvent(eventObj);
            } catch (err) {
                console.error("Failed to parse SSE JSON:", err, e.data);
            }
        };

        sseSource.onerror = (err) => {
            console.warn("SSE stream disconnected or ended:", err);
            if (sseSource) {
                sseSource.close();
                sseSource = null;
            }
            liveIndicator.classList.add("hidden");
            cancelBtn.disabled = true;
            // Poll final status
            checkSessionFinalStatus(sessionId);
        };
    }

    function handleControllerEvent(eventObj) {
        appendEventCard(eventObj);

        const eventType = eventObj.event_type || "";
        const data = eventObj.data || {};

        if (eventType === "turn_started") {
            const turn = data.turn || 0;
            const pct = Math.min(100, Math.round((turn / maxTurns) * 100));
            executionProgressBar.style.width = `${pct}%`;
            progressSummary.textContent = `Turn ${turn} / ${maxTurns} | Step: ${data.step || "Reasoning"}`;
        } else if (eventType === "tool_executed") {
            // Update traffic and summary
            if (data.requests_sent !== undefined) {
                progressSummary.textContent = `Turn ${data.turn || 0} / ${maxTurns} | Requests: ${data.requests_sent}`;
            }
        } else if (eventType === "finding_discovered") {
            incrementFindingsCounter();
            loadFindings(activeSessionId);
        } else if (eventType === "assessment_completed") {
            setAssessmentState("COMPLETED");
            executionProgressBar.style.width = "100%";
            cancelBtn.disabled = true;
            liveIndicator.classList.add("hidden");
            loadFindings(activeSessionId);
            loadTraffic(activeSessionId);
            loadReport(activeSessionId);
        } else if (eventType === "assessment_failed") {
            setAssessmentState("FAILED");
            cancelBtn.disabled = true;
            liveIndicator.classList.add("hidden");
        } else if (eventType === "assessment_cancelled") {
            setAssessmentState("CANCELLED");
            cancelBtn.disabled = true;
            liveIndicator.classList.add("hidden");
        }
    }

    function appendEventCard(eventObj) {
        const entry = document.createElement("div");
        const eventType = eventObj.event_type || "info";
        entry.className = `event-entry ${eventType}`;

        const timeStr = eventObj.timestamp ? new Date(eventObj.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
        const dataStr = typeof eventObj.data === "object" ? JSON.stringify(eventObj.data, null, 2) : String(eventObj.data || "");

        entry.innerHTML = `
            <div class="event-meta">
                <span>[${timeStr}]</span>
                <strong>${escapeHtml(eventType.toUpperCase())}</strong>
            </div>
            <pre class="event-payload">${escapeHtml(dataStr)}</pre>
        `;

        liveEventFeed.appendChild(entry);

        if (autoScrollCheckbox.checked) {
            liveEventFeed.scrollTop = liveEventFeed.scrollHeight;
        }
    }

    clearFeedBtn.addEventListener("click", () => {
        liveEventFeed.innerHTML = '<div class="empty-feed">Feed cleared. Telemetry streaming active.</div>';
    });

    async function checkSessionFinalStatus(sessionId) {
        try {
            const resp = await fetch(`/api/assessments/${sessionId}/status`);
            if (resp.ok) {
                const s = await resp.json();
                setAssessmentState(s.status || "COMPLETED");
                if (s.findings_count !== undefined) {
                    findingsCountBadge.textContent = s.findings_count;
                }
            }
        } catch (_) {}
    }

    function setAssessmentState(state) {
        const st = state.toUpperCase();
        assessmentBadge.textContent = st;
        assessmentBadge.className = `badge badge-${st.toLowerCase()}`;
        executionStateLabel.textContent = st;
        executionStateLabel.className = `badge badge-${st.toLowerCase()}`;

        if (st === "RUNNING") {
            cancelBtn.disabled = false;
            liveIndicator.classList.remove("hidden");
        } else {
            cancelBtn.disabled = true;
            liveIndicator.classList.add("hidden");
        }
    }

    function incrementFindingsCounter() {
        const count = parseInt(findingsCountBadge.textContent || "0", 10) + 1;
        findingsCountBadge.textContent = count;
    }

    // --- RECENT SESSIONS (OVERVIEW) ---
    async function loadRecentSessions() {
        try {
            const resp = await fetch("/api/assessments?limit=10");
            if (!resp.ok) return;
            const data = await resp.json();
            const sessions = data.sessions || [];

            let confirmedTotal = 0;
            let suspectedTotal = 0;
            let safeTotal = 0;

            if (sessions.length === 0) {
                sessionsTableBody.innerHTML = '<tr><td colspan="7" class="text-center">No assessments recorded yet.</td></tr>';
                document.getElementById("stat-total-sessions").textContent = "0";
                return;
            }

            document.getElementById("stat-total-sessions").textContent = sessions.length;

            sessionsTableBody.innerHTML = sessions.map(s => {
                const badgeClass = `badge-${(s.status || "idle").toLowerCase()}`;
                const dt = s.created_at ? new Date(s.created_at).toLocaleString() : "-";
                return `
                    <tr>
                        <td><a href="#" class="view-session-link" data-id="${escapeHtml(s.session_id)}">${escapeHtml(s.session_id.substring(0, 8))}...</a></td>
                        <td>${escapeHtml(s.target || "-")}</td>
                        <td><span class="badge ${badgeClass}">${escapeHtml(s.status || "IDLE")}</span></td>
                        <td>${s.turns_taken || 0}</td>
                        <td>${s.requests_sent || 0}</td>
                        <td>${dt}</td>
                        <td><button class="btn btn-secondary btn-xs select-session-btn" data-id="${escapeHtml(s.session_id)}">Open</button></td>
                    </tr>
                `;
            }).join("");

            // Attach listeners to Open buttons
            document.querySelectorAll(".select-session-btn, .view-session-link").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    e.preventDefault();
                    const sid = btn.getAttribute("data-id");
                    if (sid) selectSession(sid);
                });
            });

            // Update stats
            if (activeSessionId) {
                const fResp = await fetch(`/api/assessments/${activeSessionId}/findings`);
                if (fResp.ok) {
                    const fData = await fResp.json();
                    (fData.findings || []).forEach(f => {
                        const st = (f.status || "").toUpperCase();
                        if (st === "CONFIRMED") confirmedTotal++;
                        else if (st === "SUSPECTED") suspectedTotal++;
                        else if (st === "NOT_DEMONSTRATED") safeTotal++;
                    });
                }
            }
            document.getElementById("stat-confirmed-findings").textContent = confirmedTotal;
            document.getElementById("stat-suspected-findings").textContent = suspectedTotal;
            document.getElementById("stat-abstentions").textContent = safeTotal;

        } catch (err) {
            console.error("Failed to load sessions:", err);
        }
    }

    refreshSessionsBtn.addEventListener("click", loadRecentSessions);

    async function selectSession(sessionId) {
        activeSessionId = sessionId;
        currentSessionDisplay.textContent = sessionId;

        try {
            const resp = await fetch(`/api/assessments/${sessionId}/status`);
            if (resp.ok) {
                const s = await resp.json();
                currentTargetDisplay.textContent = s.target || "Unknown";
                setAssessmentState(s.status || "COMPLETED");
            }
        } catch (_) {}

        switchTab("security-findings");
        loadFindings(sessionId);
        loadTraffic(sessionId);
        loadReport(sessionId);
    }

    // --- TRAFFIC INSPECTOR ---
    async function loadTraffic(sessionId) {
        if (!sessionId) return;
        trafficTableBody.innerHTML = '<tr><td colspan="4" class="text-center">Loading traffic logs...</td></tr>';

        try {
            const resp = await fetch(`/api/assessments/${sessionId}/traffic`);
            if (!resp.ok) return;
            const data = await resp.json();
            cachedTraffic = data.traffic || [];

            if (cachedTraffic.length === 0) {
                trafficTableBody.innerHTML = '<tr><td colspan="4" class="text-center">No HTTP traffic recorded for this session.</td></tr>';
                trafficDetailContainer.innerHTML = '<div class="detail-placeholder">No traffic logs found.</div>';
                return;
            }

            trafficTableBody.innerHTML = cachedTraffic.map((t, idx) => {
                const statusColor = t.response_status < 400 ? "text-green" : (t.response_status < 500 ? "text-warning" : "text-danger");
                const url = t.url || "-";
                const shortUrl = url.length > 32 ? url.substring(0, 32) + "..." : url;
                return `
                    <tr class="traffic-row" data-idx="${idx}">
                        <td><strong>${escapeHtml(t.method || "GET")}</strong></td>
                        <td title="${escapeHtml(url)}">${escapeHtml(shortUrl)}</td>
                        <td class="${statusColor}">${t.response_status || "-"}</td>
                        <td>${(t.response_time_ms || 0).toFixed(0)}ms</td>
                    </tr>
                `;
            }).join("");

            // Add click handlers
            document.querySelectorAll(".traffic-row").forEach(row => {
                row.addEventListener("click", () => {
                    document.querySelectorAll(".traffic-row").forEach(r => r.classList.remove("selected"));
                    row.classList.add("selected");
                    const idx = parseInt(row.getAttribute("data-idx"), 10);
                    displayTrafficDetail(cachedTraffic[idx]);
                });
            });

            // Select first row by default
            if (cachedTraffic.length > 0) {
                const firstRow = document.querySelector(".traffic-row");
                if (firstRow) firstRow.click();
            }

        } catch (err) {
            trafficTableBody.innerHTML = `<tr><td colspan="4" class="text-center text-danger">Error loading traffic: ${err.message}</td></tr>`;
        }
    }

    function displayTrafficDetail(t) {
        if (!t) return;
        selectedTrafficStatus.textContent = `${t.method} ${t.url} [${t.response_status}]`;

        const reqHeaders = typeof t.request_headers === "object" ? JSON.stringify(t.request_headers, null, 2) : String(t.request_headers || "{}");
        const respHeaders = typeof t.response_headers === "object" ? JSON.stringify(t.response_headers, null, 2) : String(t.response_headers || "{}");
        const reqBody = typeof t.request_body === "object" ? JSON.stringify(t.request_body, null, 2) : String(t.request_body || "None");
        const respBody = typeof t.response_body === "object" ? JSON.stringify(t.response_body, null, 2) : String(t.response_body || "None");

        trafficDetailContainer.innerHTML = `
            <div>
                <h4>Request Overview</h4>
                <p><strong>Endpoint:</strong> ${escapeHtml(t.url)}</p>
                <p><strong>Timestamp:</strong> ${t.timestamp || "-"}</p>
                <p><strong>Roundtrip Latency:</strong> ${t.response_time_ms || 0} ms</p>
            </div>
            
            <h4 class="mt-3">Request Headers (Masked)</h4>
            <pre class="raw-box">${escapeHtml(reqHeaders)}</pre>

            <h4>Request Body</h4>
            <pre class="raw-box">${escapeHtml(reqBody)}</pre>

            <h4>Response Headers</h4>
            <pre class="raw-box">${escapeHtml(respHeaders)}</pre>

            <h4>Response Body</h4>
            <pre class="raw-box">${escapeHtml(respBody)}</pre>
        `;
    }

    refreshTrafficBtn.addEventListener("click", () => loadTraffic(activeSessionId));

    // --- SECURITY FINDINGS ---
    async function loadFindings(sessionId) {
        if (!sessionId) return;
        findingsList.innerHTML = '<div class="empty-feed">Loading verified security findings...</div>';

        try {
            const resp = await fetch(`/api/assessments/${sessionId}/findings`);
            if (!resp.ok) return;
            const data = await resp.json();
            cachedFindings = data.findings || [];
            findingsCountBadge.textContent = cachedFindings.length;
            renderFindings();
        } catch (err) {
            findingsList.innerHTML = `<div class="empty-feed text-danger">Error loading findings: ${err.message}</div>`;
        }
    }

    function renderFindings() {
        const filterVal = findingsStatusFilter.value;
        const filtered = cachedFindings.filter(f => {
            if (filterVal === "ALL") return true;
            return (f.status || "").toUpperCase() === filterVal;
        });

        if (filtered.length === 0) {
            findingsList.innerHTML = '<div class="empty-feed">No findings matching the selected filter.</div>';
            return;
        }

        findingsList.innerHTML = filtered.map(f => {
            const st = (f.status || "CONFIRMED").toUpperCase();
            const badgeClass = `badge-${st.toLowerCase()}`;
            return `
                <div class="finding-card ${st}">
                    <div class="finding-header">
                        <div class="finding-title">${escapeHtml(f.category || "Security Observation")} &mdash; ${escapeHtml(f.endpoint || "General")}</div>
                        <span class="badge ${badgeClass}">${st}</span>
                    </div>
                    <div class="finding-body">
                        <div><strong>Description:</strong> ${escapeHtml(f.description || "No description")}</div>
                        ${f.parameter ? `<div><strong>Affected Parameter:</strong> <code>${escapeHtml(f.parameter)}</code></div>` : ""}
                        ${f.evidence ? `<div class="finding-evidence"><strong>Evidence Trace:</strong><br>${escapeHtml(f.evidence)}</div>` : ""}
                        ${f.remediation ? `<div class="mt-3"><strong>Remediation Advice:</strong> ${escapeHtml(f.remediation)}</div>` : ""}
                    </div>
                </div>
            `;
        }).join("");
    }

    findingsStatusFilter.addEventListener("change", renderFindings);
    refreshFindingsBtn.addEventListener("click", () => loadFindings(activeSessionId));

    // --- REPORT MANAGEMENT ---
    async function loadReport(sessionId) {
        if (!sessionId) return;
        reportPreview.textContent = "Loading report markdown preview...";

        try {
            const resp = await fetch(`/api/assessments/${sessionId}/report`);
            if (!resp.ok) {
                reportPreview.textContent = "No final report generated yet.";
                return;
            }
            const data = await resp.json();
            reportPreview.textContent = data.report_markdown || "Empty report.";
        } catch (err) {
            reportPreview.textContent = `Error loading report: ${err.message}`;
        }
    }

    downloadReportBtn.addEventListener("click", () => {
        if (!activeSessionId) {
            alert("No active session to download report for.");
            return;
        }
        window.location.href = `/api/assessments/${activeSessionId}/report/download`;
    });

    refreshReportBtn.addEventListener("click", () => loadReport(activeSessionId));

    // Utility
    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Startup
    checkSystemHealth();
    loadRecentSessions();
    setInterval(checkSystemHealth, 10000);
});

