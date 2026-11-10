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
    const themeToggleBtn = document.getElementById("theme-toggle-btn");

    // =========================================================================
    // THEME SWITCHER & TOAST NOTIFICATION SYSTEM
    // =========================================================================
    const savedTheme = localStorage.getItem("dashboard-theme") || "dark-theme";
    document.body.className = savedTheme;
    if (themeToggleBtn) {
        themeToggleBtn.textContent = savedTheme === "light-theme" ? "🌙 Dark" : "☀️ Light";
        themeToggleBtn.addEventListener("click", () => {
            const isLight = document.body.classList.contains("light-theme");
            const newTheme = isLight ? "dark-theme" : "light-theme";
            document.body.className = newTheme;
            localStorage.setItem("dashboard-theme", newTheme);
            themeToggleBtn.textContent = newTheme === "light-theme" ? "🌙 Dark" : "☀️ Light";
            showToast(`Switched to ${newTheme === "light-theme" ? "Light" : "Dark"} Theme`, "info", 2000);
        });
    }

    function showToast(message, type = "info", duration = 3500) {
        const container = document.getElementById("toast-container");
        if (!container) return;
        const toast = document.createElement("div");
        toast.className = `toast-message toast-${type}`;
        const icons = { success: "✅", error: "❌", warning: "⚠️", info: "ℹ️" };
        toast.innerHTML = `<span>${icons[type] || "ℹ️"}</span><span>${message}</span>`;
        container.appendChild(toast);
        setTimeout(() => {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, duration);
    }

    function showConfirmModal(title, message, onConfirm, isDanger = true) {
        const backdrop = document.getElementById("confirm-modal-backdrop");
        const titleEl = document.getElementById("confirm-modal-title");
        const msgEl = document.getElementById("confirm-modal-message");
        const proceedBtn = document.getElementById("confirm-modal-proceed");
        const cancelModalBtn = document.getElementById("confirm-modal-cancel");
        const closeBtn = document.getElementById("confirm-modal-close");

        if (!backdrop || !proceedBtn) {
            if (window.confirm(`${title}\n\n${message}`)) {
                onConfirm();
            }
            return;
        }

        titleEl.textContent = title;
        msgEl.textContent = message;
        proceedBtn.className = isDanger ? "btn btn-danger btn-sm" : "btn btn-primary btn-sm";
        backdrop.classList.remove("hidden");

        const cleanup = () => {
            backdrop.classList.add("hidden");
            proceedBtn.onclick = null;
            cancelModalBtn.onclick = null;
            closeBtn.onclick = null;
        };

        proceedBtn.onclick = () => {
            cleanup();
            onConfirm();
        };
        cancelModalBtn.onclick = cleanup;
        closeBtn.onclick = cleanup;
    }

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
    const trafficSearchInput = document.getElementById("traffic-search-input");
    const trafficPrevBtn = document.getElementById("traffic-prev-btn");
    const trafficNextBtn = document.getElementById("traffic-next-btn");
    const trafficPageInfo = document.getElementById("traffic-page-info");
    let trafficCurrentPage = 1;
    const trafficPageSize = 25;
    let trafficSearchFilter = "";

    // Findings Elements
    const findingsList = document.getElementById("findings-list");
    const findingsStatusFilter = document.getElementById("findings-status-filter");
    const findingsSearchInput = document.getElementById("findings-search-input");
    const findingsMatchCount = document.getElementById("findings-match-count");
    const refreshFindingsBtn = document.getElementById("refresh-findings-btn");
    let findingsSearchFilter = "";

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
        } else if (tabName === "discovered-endpoints" && activeSessionId) {
            loadEndpoints(activeSessionId);
        } else if (tabName === "reports" && activeSessionId) {
            loadReport(activeSessionId);
        } else if (tabName === "dashboard") {
            loadRecentSessions();
        } else if (tabName === "policies") {
            loadPolicyMetrics();
            loadPolicies();
            loadAuditLog();
            loadQuickScopeStatus();
        } else if (tabName === "new-assessment") {
            loadActivePoliciesDropdown();
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

    // Toggle Authentication Method Inputs
    const authTypeSelect = document.getElementById("auth_type");
    const authBearerGroup = document.getElementById("auth-bearer-group");
    const authApiKeyGroup = document.getElementById("auth-apikey-group");
    const authBasicGroup = document.getElementById("auth-basic-group");
    const authCustomGroup = document.getElementById("auth-custom-group");

    if (authTypeSelect) {
        authTypeSelect.addEventListener("change", () => {
            const val = authTypeSelect.value;
            if (authBearerGroup) authBearerGroup.style.display = (val === "bearer") ? "block" : "none";
            if (authApiKeyGroup) authApiKeyGroup.style.display = (val === "api_key") ? "block" : "none";
            if (authBasicGroup) authBasicGroup.style.display = (val === "basic") ? "block" : "none";
            if (authCustomGroup) authCustomGroup.style.display = (val === "custom") ? "block" : "none";
        });
    }

    // OWASP Categories Select All / Clear All
    const btnSelectAllOwasp = document.getElementById("btn-select-all-owasp");
    const btnClearAllOwasp = document.getElementById("btn-clear-all-owasp");
    if (btnSelectAllOwasp) {
        btnSelectAllOwasp.addEventListener("click", () => {
            document.querySelectorAll('input[name="owasp_cat"]').forEach(cb => cb.checked = true);
        });
    }
    if (btnClearAllOwasp) {
        btnClearAllOwasp.addEventListener("click", () => {
            document.querySelectorAll('input[name="owasp_cat"]').forEach(cb => cb.checked = false);
        });
    }

    // --- LAUNCH ASSESSMENT ---
    assessmentForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        startStatusMsg.textContent = "Initiating assessment...";
        startStatusMsg.style.color = "var(--accent-cyan)";

        // Resolve credentials based on selected auth type
        const aType = authTypeSelect ? authTypeSelect.value : "none";
        const authCreds = {};
        if (aType === "bearer") {
            authCreds.token = (document.getElementById("auth_bearer_token")?.value || "").trim();
        } else if (aType === "api_key") {
            authCreds.header_name = (document.getElementById("auth_api_key_name")?.value || "X-API-Key").trim();
            authCreds.api_key = (document.getElementById("auth_api_key_val")?.value || "").trim();
        } else if (aType === "basic") {
            authCreds.username = (document.getElementById("auth_basic_user")?.value || "").trim();
            authCreds.password = (document.getElementById("auth_basic_pass")?.value || "").trim();
        }

        // Selected OWASP Categories
        const selectedCats = Array.from(document.querySelectorAll('input[name="owasp_cat"]:checked')).map(cb => cb.value);

        const payload = {
            target_url: document.getElementById("target_url").value.trim(),
            allowed_hosts: document.getElementById("allowed_hosts").value.split(",").map(s => s.trim()).filter(Boolean),
            assessment_name: document.getElementById("assessment_name").value.trim(),
            brain_mode: brainModeSelect.value,
            remote_endpoint: document.getElementById("remote_endpoint").value.trim() || null,
            spec_source: document.getElementById("spec_source").value.trim() || null,
            assessment_type: document.getElementById("assessment_type")?.value || "auto",
            assessment_depth: document.getElementById("assessment_depth")?.value || "standard",
            auth_type: aType,
            auth_credentials: Object.keys(authCreds).length > 0 ? authCreds : null,
            auth_context: (document.getElementById("auth_context") ? document.getElementById("auth_context").value.trim() : "") || null,
            selected_categories: selectedCats.length > 0 ? selectedCats : null,
            timeout_seconds: parseInt(document.getElementById("timeout_seconds")?.value || "120", 10),
            max_turns: parseInt(document.getElementById("max_turns").value, 10),
            max_requests: parseInt(document.getElementById("max_requests").value, 10),
            max_model_calls: parseInt(document.getElementById("max_model_calls").value, 10),
            zap_active_scan: document.getElementById("zap_active_scan").checked,
            policy_id: document.getElementById("assessment_policy_id")?.value ? parseInt(document.getElementById("assessment_policy_id").value, 10) : null,
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
    cancelBtn.addEventListener("click", () => {
        if (!activeSessionId) return;
        showConfirmModal(
            "Cancel Security Assessment",
            `Are you sure you want to stop the active assessment for session '${activeSessionId}'? Current tool execution will halt immediately.`,
            async () => {
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
                        showToast("Assessment cancelled successfully", "warning");
                    }
                } catch (err) {
                    console.error("Cancel failed:", err);
                    showToast("Failed to send cancellation request", "error");
                } finally {
                    cancelBtn.textContent = "Cancel Scan";
                }
            },
            true
        );
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

        const rawType = eventObj.event_type || eventObj.type || "";
        const eventType = String(rawType).toLowerCase().trim();
        const data = eventObj.data || {};

        if (eventType === "turn_started" || eventType === "budget_update") {
            const turn = data.turn || 0;
            const pct = Math.min(100, Math.round((turn / maxTurns) * 100));
            executionProgressBar.style.width = `${pct}%`;
            progressSummary.textContent = `Turn ${turn} / ${maxTurns} | Requests: ${data.requests_sent || 0}`;
        } else if (eventType === "tool_executed") {
            // Update traffic and summary
            if (data.requests_sent !== undefined) {
                progressSummary.textContent = `Turn ${data.turn || 0} / ${maxTurns} | Requests: ${data.requests_sent}`;
            }
            if (activeSessionId) {
                loadTraffic(activeSessionId);
            }
        } else if (eventType === "finding_recorded" || eventType === "finding_discovered") {
            incrementFindingsCounter();
            if (activeSessionId) {
                loadFindings(activeSessionId);
            }
            showToast("🚨 Security Vulnerability Discovered!", "warning");
        } else if (eventType === "assessment_completed") {
            setAssessmentState("COMPLETED");
            executionProgressBar.style.width = "100%";
            cancelBtn.disabled = true;
            liveIndicator.classList.add("hidden");
            if (activeSessionId) {
                loadFindings(activeSessionId);
                loadTraffic(activeSessionId);
                loadReport(activeSessionId);
            }
            showToast("Assessment completed. Executive report ready.", "success");
        } else if (eventType === "assessment_failed") {
            setAssessmentState("FAILED");
            cancelBtn.disabled = true;
            liveIndicator.classList.add("hidden");
            showToast("Assessment failed: " + (data.error || "Execution error"), "error");
        } else if (eventType === "assessment_cancelled") {
            setAssessmentState("CANCELLED");
            cancelBtn.disabled = true;
            liveIndicator.classList.add("hidden");
            showToast("Assessment cancelled", "warning");
        }
    }

    function appendEventCard(eventObj) {
        const entry = document.createElement("div");
        const rawType = eventObj.event_type || eventObj.type || "info";
        const eventType = String(rawType).toLowerCase().trim();
        entry.className = `event-entry ${eventType}`;

        const timeStr = eventObj.timestamp ? new Date(eventObj.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
        const data = eventObj.data || {};
        const dataStr = typeof data === "object" ? JSON.stringify(data, null, 2) : String(data || "");

        let titleHtml = `<strong>${escapeHtml(rawType.toUpperCase())}</strong>`;
        let contentHtml = `<pre class="event-payload">${escapeHtml(dataStr)}</pre>`;

        if (eventType === "action_proposed" || eventType.includes("action_planned") || eventType.includes("tool_call")) {
            const proposal = data.action_proposal || data;
            const turn = data.turn || proposal.turn || "";
            const tool = proposal.tool_name || proposal.tool || "httpx_request";
            const reasoning = proposal.reasoning || proposal.thought || "Analyzing target attack surface.";
            const args = proposal.arguments || {};
            const method = (args.method || proposal.method || "GET").toUpperCase();
            const url = args.url || args.target || proposal.target || "";

            titleHtml = `<strong style="color: #c084fc;">🧠 AI ReAct Loop — Turn ${turn ? turn : ""}: Proposing Action</strong>`;
            contentHtml = `
                <div style="background: rgba(168, 85, 247, 0.08); border-left: 3px solid #a855f7; padding: 0.6rem 0.8rem; margin-top: 0.35rem; border-radius: 4px; font-size: 0.88rem; color: #e9d5ff;">
                    <div style="margin-bottom: 0.35rem;"><strong>Analysis & Strategy:</strong> ${escapeHtml(reasoning)}</div>
                    <div style="font-size: 0.84rem; color: #cbd5e1;">
                        <span style="color: #38bdf8; font-weight: 600;">⚙️ Selected Tool:</span> <code style="color: #7dd3fc; background: #0f172a; padding: 2px 5px; border-radius: 3px;">${escapeHtml(tool)}</code>
                        &nbsp;|&nbsp;
                        <span style="color: #fbbf24; font-weight: 600;">Method:</span> <code style="color: #fde047; background: #0f172a; padding: 2px 5px; border-radius: 3px;">${escapeHtml(method)}</code>
                        &nbsp;|&nbsp;
                        <span style="color: #a7f3d0; font-weight: 600;">Target:</span> <code style="color: #6ee7b7; background: #0f172a; padding: 2px 5px; border-radius: 3px;">${escapeHtml(url || "Endpoint")}</code>
                    </div>
                </div>
            `;
        } else if (eventType.includes("tool_executed") || eventType === "action_executed") {
            const tool = data.tool_name || data.tool || "tool";
            const status = data.status_code !== undefined && data.status_code !== null ? `HTTP ${data.status_code}` : (data.success ? "SUCCESS" : "FAILED / NO_RESPONSE");
            const dur = data.duration_ms !== undefined ? `${data.duration_ms}ms` : "";
            const isOk = data.success !== false && (data.status_code === null || (data.status_code >= 200 && data.status_code < 400));
            const statusColor = isOk ? "#4ade80" : (data.status_code === 404 ? "#fbbf24" : "#f87171");

            titleHtml = `<strong style="color: ${statusColor};">⚡ Tool Executed: ${escapeHtml(tool)} [${escapeHtml(status)}${dur ? " - " + dur : ""}]</strong>`;
            contentHtml = `
                <div style="background: rgba(30, 41, 59, 0.6); border-left: 3px solid ${statusColor}; padding: 0.5rem 0.75rem; margin-top: 0.35rem; border-radius: 4px; font-size: 0.85rem; color: #94a3b8;">
                    <div>Tool <code>${escapeHtml(tool)}</code> completed in <strong style="color: #f1f5f9;">${escapeHtml(dur || "0ms")}</strong>. Return status: <span style="color: ${statusColor}; font-weight: 600;">${escapeHtml(status)}</span>. Server response passed back to AI brain for evidence analysis.</div>
                </div>
            `;
        } else if (eventType === "policy_decision") {
            const approved = data.approved !== false;
            titleHtml = approved 
                ? `<strong style="color: #34d399;">🛡️ Policy Guardrail Check: Approved</strong>`
                : `<strong style="color: #f87171;">🛡️ Policy Guardrail Check: Blocked (${escapeHtml(data.reason || "Out of scope")})</strong>`;
            contentHtml = `<div style="font-size: 0.82rem; color: #94a3b8; padding-top: 0.2rem;">Guardrails validated destination and parameter safety bounds. (${escapeHtml(data.reason || "Authorized")})</div>`;
        } else if (eventType === "finding_recorded" || eventType.includes("finding")) {
            const f = data.finding || data;
            const cat = f.category || f.vulnerability_type || "Security Finding";
            const status = f.status || "CONFIRMED";
            const endpoint = f.endpoint || f.target || "";
            const notes = f.notes || f.description || f.evidence_notes || "Vulnerability evidence recorded and verified.";

            titleHtml = `<strong style="color: #ef4444;">🚨 Vulnerability Discovered: ${escapeHtml(cat)} [${escapeHtml(status)}]</strong>`;
            contentHtml = `
                <div style="background: rgba(239, 68, 68, 0.12); border-left: 3px solid #ef4444; padding: 0.6rem 0.8rem; margin-top: 0.35rem; border-radius: 4px; font-size: 0.88rem; color: #fca5a5;">
                    <div><strong>Vulnerable Endpoint:</strong> <code style="color: #fecaca; background: #450a0a; padding: 2px 4px; border-radius: 3px;">${escapeHtml(endpoint)}</code></div>
                    <div style="margin-top: 0.3rem;"><strong>AI Evidence Analysis:</strong> ${escapeHtml(notes)}</div>
                </div>
            `;
        } else if (eventType === "phase_change") {
            const phase = data.phase || "EXECUTION";
            const target = data.target || "";
            const epsCount = data.endpoints_count !== undefined ? `(${data.endpoints_count} endpoints mapped)` : "";
            titleHtml = `<strong style="color: #38bdf8;">📍 Phase Shift ➔ ${escapeHtml(phase)}</strong>`;
            contentHtml = `<div style="color: #7dd3fc; font-size: 0.84rem; padding: 0.2rem 0;">Transitioned testing controller to <strong>${escapeHtml(phase)}</strong> ${escapeHtml(epsCount)} ${escapeHtml(target ? "for " + target : "")}</div>`;
        } else if (eventType === "budget_update") {
            const turn = data.turn || 0;
            const sent = data.requests_sent || 0;
            const remaining = data.requests_remaining !== undefined ? data.requests_remaining : "";
            titleHtml = `<strong style="color: #94a3b8;">📊 Assessment Budget: Turn ${turn} (Requests: ${sent} sent, ${remaining} remaining)</strong>`;
            contentHtml = "";
        } else if (eventType === "assessment_completed") {
            const turns = data.turns_taken || 0;
            const findings = data.findings_count || 0;
            const reason = data.termination_reason || "Completed";
            titleHtml = `<strong style="color: #10b981;">🏁 Assessment Completed [${escapeHtml(reason)}]</strong>`;
            contentHtml = `<div style="background: rgba(16, 185, 129, 0.1); border-left: 3px solid #10b981; padding: 0.5rem 0.75rem; margin-top: 0.35rem; border-radius: 4px; font-size: 0.85rem; color: #6ee7b7;">Finished execution in <strong>${turns} turns</strong> with <strong>${findings} verified findings</strong>. Reason: ${escapeHtml(reason)}. Executive report generated.</div>`;
        }

        entry.innerHTML = `
            <div class="event-meta" style="display: flex; justify-content: space-between; align-items: center;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span>[${timeStr}]</span>
                    ${titleHtml}
                </div>
            </div>
            ${contentHtml}
        `;

        liveEventFeed.appendChild(entry);

        // Bounded feed to avoid memory bloat
        const MAX_FEED_ENTRIES = 200;
        while (liveEventFeed.children.length > MAX_FEED_ENTRIES) {
            liveEventFeed.removeChild(liveEventFeed.firstElementChild);
        }

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

            // Update stats efficiently via direct SQL status aggregations
            if (activeSessionId) {
                const sResp = await fetch(`/api/assessments/${activeSessionId}/status`);
                if (sResp.ok) {
                    const sData = await sResp.json();
                    confirmedTotal = sData.confirmed_count !== undefined ? sData.confirmed_count : 0;
                    suspectedTotal = sData.suspected_count !== undefined ? sData.suspected_count : 0;
                    safeTotal = sData.safe_count !== undefined ? sData.safe_count : 0;
                }
            }
            document.getElementById("stat-confirmed-findings").textContent = confirmedTotal;
            document.getElementById("stat-suspected-findings").textContent = suspectedTotal;
            document.getElementById("stat-abstentions").textContent = safeTotal;

            // Populate Comparison Dropdowns
            const compareA = document.getElementById("compare-session-a");
            const compareB = document.getElementById("compare-session-b");
            if (compareA && compareB && sessions.length > 0) {
                const prevA = compareA.value;
                const prevB = compareB.value;
                const opts = '<option value="">Select Session...</option>' + sessions.map(s => `
                    <option value="${escapeHtml(s.session_id)}">${escapeHtml(s.session_id.substring(0, 12))}... (${escapeHtml(s.target || "Target")}) - ${escapeHtml(s.status)}</option>
                `).join("");
                compareA.innerHTML = opts;
                compareB.innerHTML = opts;
                if (prevA) compareA.value = prevA;
                if (prevB) compareB.value = prevB;
            }

        } catch (err) {
            console.error("Failed to load sessions:", err);
        }
    }

    refreshSessionsBtn.addEventListener("click", loadRecentSessions);

    // --- SESSION COMPARISON RUNNER ---
    const runCompareBtn = document.getElementById("run-compare-btn");
    if (runCompareBtn) {
        runCompareBtn.addEventListener("click", async () => {
            const sidA = document.getElementById("compare-session-a").value;
            const sidB = document.getElementById("compare-session-b").value;
            const statusMsg = document.getElementById("compare-status-msg");
            const resultsContainer = document.getElementById("compare-results-container");

            if (!sidA || !sidB) {
                statusMsg.textContent = "Please select both Session A and Session B.";
                statusMsg.style.color = "var(--status-red)";
                return;
            }
            if (sidA === sidB) {
                statusMsg.textContent = "Please select two distinct sessions to compare.";
                statusMsg.style.color = "var(--status-amber)";
                return;
            }

            statusMsg.textContent = "Comparing sessions...";
            statusMsg.style.color = "var(--accent-cyan)";

            try {
                const resp = await fetch(`/api/assessments/compare?session_a=${encodeURIComponent(sidA)}&session_b=${encodeURIComponent(sidB)}`);
                const data = await resp.json();
                if (!resp.ok || data.error) {
                    statusMsg.textContent = `Comparison error: ${data.error || "Failed"}`;
                    statusMsg.style.color = "var(--status-red)";
                    return;
                }

                statusMsg.textContent = "Comparison complete!";
                statusMsg.style.color = "var(--status-green)";
                resultsContainer.style.display = "block";

                // Update cards
                const riskDelta = data.risk_delta;
                const deltaElem = document.getElementById("diff-risk-delta");
                deltaElem.textContent = (riskDelta > 0 ? `+${riskDelta}` : `${riskDelta}`);
                deltaElem.style.color = riskDelta > 0 ? "var(--status-red)" : (riskDelta < 0 ? "var(--status-green)" : "var(--text-light)");
                document.getElementById("diff-risk-status").textContent = data.status_change;

                document.getElementById("diff-new-count").textContent = data.summary_counts.new;
                document.getElementById("diff-resolved-count").textContent = data.summary_counts.resolved;
                document.getElementById("diff-persistent-count").textContent = data.summary_counts.persistent;

                // Render table
                const tbody = document.getElementById("compare-details-tbody");
                const allDiffs = [
                    ...data.new_findings.map(f => ({ ...f, diff_type: "NEW (Regression)", badge: "badge-critical" })),
                    ...data.resolved_findings.map(f => ({ ...f, diff_type: "RESOLVED (Fixed)", badge: "badge-confirmed" })),
                    ...data.persistent_findings.map(f => ({ ...f, diff_type: "PERSISTENT", badge: "badge-suspected" })),
                ];

                if (allDiffs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="text-center">No vulnerability differences observed between selected runs.</td></tr>';
                } else {
                    tbody.innerHTML = allDiffs.map(f => `
                        <tr>
                            <td><span class="badge ${f.badge}">${escapeHtml(f.diff_type)}</span></td>
                            <td><code>${escapeHtml(f.endpoint || "/")}</code></td>
                            <td><strong>${escapeHtml(f.category || "Finding")}</strong></td>
                            <td><span class="badge badge-${(f.severity || 'info').toLowerCase()}">${escapeHtml(f.severity || "INFO")}</span></td>
                            <td>${escapeHtml(f.evidence_notes || f.notes || "Analysis available")}</td>
                        </tr>
                    `).join("");
                }
            } catch (err) {
                statusMsg.textContent = `Comparison failed: ${err.message}`;
                statusMsg.style.color = "var(--status-red)";
            }
        });
    }

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

    // --- TRAFFIC INSPECTOR (PAGINATED & FILTERABLE) ---
    function getFilteredTraffic() {
        if (!trafficSearchFilter) return cachedTraffic;
        const q = trafficSearchFilter.toLowerCase();
        return cachedTraffic.filter(t => {
            const m = (t.method || "").toLowerCase();
            const u = (t.url || "").toLowerCase();
            const s = String(t.response_status || "");
            return m.includes(q) || u.includes(q) || s.includes(q);
        });
    }

    function renderTraffic() {
        const filtered = getFilteredTraffic();
        const totalItems = filtered.length;
        const totalPages = Math.max(1, Math.ceil(totalItems / trafficPageSize));

        if (trafficCurrentPage > totalPages) trafficCurrentPage = totalPages;
        if (trafficCurrentPage < 1) trafficCurrentPage = 1;

        if (trafficPageInfo) {
            trafficPageInfo.textContent = `Page ${trafficCurrentPage} / ${totalPages} (${totalItems} logs)`;
        }
        if (trafficPrevBtn) trafficPrevBtn.disabled = (trafficCurrentPage <= 1);
        if (trafficNextBtn) trafficNextBtn.disabled = (trafficCurrentPage >= totalPages);

        if (totalItems === 0) {
            trafficTableBody.innerHTML = '<tr><td colspan="4" class="text-center">No matching traffic logs.</td></tr>';
            trafficDetailContainer.innerHTML = '<div class="detail-placeholder">No matching traffic logs found.</div>';
            return;
        }

        const startIdx = (trafficCurrentPage - 1) * trafficPageSize;
        const pageItems = filtered.slice(startIdx, startIdx + trafficPageSize);

        trafficTableBody.innerHTML = pageItems.map((t, localIdx) => {
            const globalIdx = startIdx + localIdx;
            const statusColor = t.response_status < 400 ? "text-green" : (t.response_status < 500 ? "text-warning" : "text-danger");
            const url = t.url || "-";
            const shortUrl = url.length > 32 ? url.substring(0, 32) + "..." : url;
            return `
                <tr class="traffic-row" data-idx="${globalIdx}">
                    <td><strong>${escapeHtml(t.method || "GET")}</strong></td>
                    <td title="${escapeHtml(url)}">${escapeHtml(shortUrl)}</td>
                    <td class="${statusColor}">${t.response_status || "-"}</td>
                    <td>${(t.response_time_ms || 0).toFixed(0)}ms</td>
                </tr>
            `;
        }).join("");

        // Attach click handlers
        document.querySelectorAll(".traffic-row").forEach(row => {
            row.addEventListener("click", () => {
                document.querySelectorAll(".traffic-row").forEach(r => r.classList.remove("selected"));
                row.classList.add("selected");
                const idx = parseInt(row.getAttribute("data-idx"), 10);
                displayTrafficDetail(filtered[idx]);
            });
        });

        // Select first visible row on page load
        const firstRow = document.querySelector(".traffic-row");
        if (firstRow) firstRow.click();
    }

    if (trafficSearchInput) {
        trafficSearchInput.addEventListener("input", () => {
            trafficSearchFilter = trafficSearchInput.value.trim();
            trafficCurrentPage = 1;
            renderTraffic();
        });
    }

    if (trafficPrevBtn) {
        trafficPrevBtn.addEventListener("click", () => {
            if (trafficCurrentPage > 1) {
                trafficCurrentPage--;
                renderTraffic();
            }
        });
    }

    if (trafficNextBtn) {
        trafficNextBtn.addEventListener("click", () => {
            trafficCurrentPage++;
            renderTraffic();
        });
    }

    async function loadTraffic(sessionId) {
        if (!sessionId) return;
        trafficTableBody.innerHTML = '<tr><td colspan="4" class="text-center">Loading traffic logs...</td></tr>';

        try {
            const resp = await fetch(`/api/assessments/${sessionId}/traffic`);
            if (!resp.ok) return;
            const data = await resp.json();
            cachedTraffic = data.traffic || [];
            trafficCurrentPage = 1;

            if (cachedTraffic.length === 0) {
                trafficTableBody.innerHTML = '<tr><td colspan="4" class="text-center">No HTTP traffic recorded for this session.</td></tr>';
                trafficDetailContainer.innerHTML = '<div class="detail-placeholder">No traffic logs found.</div>';
                if (trafficPageInfo) trafficPageInfo.textContent = "Page 1 / 1 (0 logs)";
                if (trafficPrevBtn) trafficPrevBtn.disabled = true;
                if (trafficNextBtn) trafficNextBtn.disabled = true;
                return;
            }

            renderTraffic();
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

    // --- SECURITY FINDINGS (SEARCHABLE & FILTERABLE) ---
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
        const q = (findingsSearchFilter || "").toLowerCase();

        const filtered = cachedFindings.filter(f => {
            if (filterVal !== "ALL" && (f.status || "").toUpperCase() !== filterVal) {
                return false;
            }
            if (!q) return true;
            const cat = (f.category || "").toLowerCase();
            const ep = (f.endpoint || "").toLowerCase();
            const rule = (f.verification_rule || "").toLowerCase();
            const notes = (f.evidence_notes || f.description || "").toLowerCase();
            const cwe = (f.cwe_id || "").toLowerCase();
            return cat.includes(q) || ep.includes(q) || rule.includes(q) || notes.includes(q) || cwe.includes(q);
        });

        if (findingsMatchCount) {
            findingsMatchCount.textContent = `${filtered.length} match${filtered.length === 1 ? "" : "es"}`;
        }

        if (filtered.length === 0) {
            findingsList.innerHTML = '<div class="empty-feed">No findings matching the selected filter.</div>';
            return;
        }

        findingsList.innerHTML = filtered.map(f => {
            const st = (f.status || "CONFIRMED").toUpperCase();
            const badgeClass = `badge-${st.toLowerCase()}`;
            const sev = (f.severity || "INFORMATIONAL").toUpperCase();
            const sevBadgeClass = `badge-${sev.toLowerCase()}`;
            const cvss = f.cvss_score ? `CVSS ${f.cvss_score}` : "";
            const cwe = f.cwe_id ? `<code>${escapeHtml(f.cwe_id)}</code>` : "";
            const rule = f.verification_rule ? `<span class="badge badge-secondary">${escapeHtml(f.verification_rule)}</span>` : "";

            return `
                <div class="finding-card ${st}">
                    <div class="finding-header">
                        <div class="finding-title">
                            <span class="badge ${sevBadgeClass}">${sev}</span>
                            ${cvss ? `<span class="badge badge-secondary">${cvss}</span>` : ""}
                            ${cwe}
                            <strong>${escapeHtml(f.category || "Security Observation")}</strong> &mdash; <code>${escapeHtml(f.endpoint || "General")}</code>
                        </div>
                        <div class="finding-badges">
                            ${rule}
                            <span class="badge ${badgeClass}">${st}</span>
                        </div>
                    </div>
                    <div class="finding-body">
                        <div><strong>Verification Proof / Analysis:</strong> ${escapeHtml(f.evidence_notes || f.description || "Baseline probe analysis")}</div>
                        ${f.technical_impact ? `<div class="mt-2 text-danger"><strong>Technical Impact:</strong> ${escapeHtml(f.technical_impact)}</div>` : ""}
                        ${f.reproduction_steps ? `<div class="mt-2"><strong>Safe Reproduction Steps:</strong><pre class="raw-box mt-1"><code>${escapeHtml(f.reproduction_steps)}</code></pre></div>` : ""}
                        ${f.remediation ? `<div class="mt-2 text-warning"><strong>Remediation Guidance:</strong> ${escapeHtml(f.remediation)}</div>` : ""}
                    </div>
                </div>
            `;
        }).join("");
    }

    if (findingsSearchInput) {
        findingsSearchInput.addEventListener("input", () => {
            findingsSearchFilter = findingsSearchInput.value.trim();
            renderFindings();
        });
    }

    findingsStatusFilter.addEventListener("change", renderFindings);
    refreshFindingsBtn.addEventListener("click", () => loadFindings(activeSessionId));

    // --- DISCOVERED ENDPOINTS ---
    async function loadEndpoints(sessionId) {
        if (!sessionId) return;
        const endpointsTableBody = document.getElementById("endpoints-table-body");
        const endpointsBadge = document.getElementById("endpoints-count-badge");
        if (!endpointsTableBody) return;

        endpointsTableBody.innerHTML = '<tr><td colspan="4" class="text-center">Loading cataloged endpoints...</td></tr>';

        try {
            const resp = await fetch(`/api/assessments/${sessionId}/endpoints`);
            if (!resp.ok) return;
            const data = await resp.json();
            const endpoints = data.endpoints || [];
            if (endpointsBadge) endpointsBadge.textContent = endpoints.length;

            if (endpoints.length === 0) {
                endpointsTableBody.innerHTML = '<tr><td colspan="4" class="text-center">No endpoints cataloged yet for this session.</td></tr>';
                return;
            }

            endpointsTableBody.innerHTML = endpoints.map(ep => `
                <tr>
                    <td><strong>${escapeHtml(ep.method || "GET")}</strong></td>
                    <td><code>${escapeHtml(ep.path || "-")}</code></td>
                    <td><span class="badge badge-secondary">${escapeHtml(ep.source || "Discovered")}</span></td>
                    <td>${escapeHtml(ep.summary || "Endpoint identified for automated testing")}</td>
                </tr>
            `).join("");
        } catch (err) {
            endpointsTableBody.innerHTML = `<tr><td colspan="4" class="text-center text-danger">Error loading endpoints: ${err.message}</td></tr>`;
        }
    }

    const refreshEndpointsBtn = document.getElementById("refresh-endpoints-btn");
    if (refreshEndpointsBtn) {
        refreshEndpointsBtn.addEventListener("click", () => loadEndpoints(activeSessionId));
    }

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

    const downloadReportJsonBtn = document.getElementById("download-report-json-btn");
    if (downloadReportJsonBtn) {
        downloadReportJsonBtn.addEventListener("click", () => {
            if (!activeSessionId) {
                alert("No active session to download report for.");
                return;
            }
            window.open(`/api/assessments/${activeSessionId}/report/json`, "_blank");
        });
    }

    const viewReportHtmlBtn = document.getElementById("view-report-html-btn");
    if (viewReportHtmlBtn) {
        viewReportHtmlBtn.addEventListener("click", () => {
            if (!activeSessionId) {
                alert("No active session to view report for.");
                return;
            }
            window.open(`/api/assessments/${activeSessionId}/report/html`, "_blank");
        });
    }

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

    // Authentication Management
    let currentUser = null;
    let csrfToken = null;

    async function checkAuthStatus() {
        try {
            const resp = await fetch("/api/auth/status");
            const data = await resp.json();
            const userBadge = document.getElementById("auth-user-badge");
            const loginLink = document.getElementById("auth-login-link");
            const logoutBtn = document.getElementById("auth-logout-btn");

            if (data.authenticated && data.user) {
                currentUser = data.user;
                csrfToken = data.csrf_token;
                if (userBadge) {
                    userBadge.textContent = `${data.user.username} (${data.user.role.toUpperCase()})`;
                    userBadge.classList.remove("hidden");
                }
                if (loginLink) loginLink.classList.add("hidden");
                if (logoutBtn) logoutBtn.classList.remove("hidden");
            } else {
                currentUser = null;
                csrfToken = null;
                if (userBadge) userBadge.classList.add("hidden");
                if (loginLink) loginLink.classList.remove("hidden");
                if (logoutBtn) logoutBtn.classList.add("hidden");
            }
        } catch (err) {
            console.debug("Auth status check failed", err);
        }
    }

    const authLogoutBtn = document.getElementById("auth-logout-btn");
    if (authLogoutBtn) {
        authLogoutBtn.addEventListener("click", async () => {
            try {
                await fetch("/api/auth/logout", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRF-Token": csrfToken || "",
                    }
                });
                window.location.reload();
            } catch (err) {
                console.error("Logout failed", err);
            }
        });
    }

    // ==========================================
    // POLICY & TARGET AUTHORIZATION MANAGEMENT
    // ==========================================

    const ALL_KNOWN_TOOLS = [
        "http_request",
        "httpx_request",
        "openapi_parser",
        "jwt_inspector",
        "parameter_fuzzer",
        "zap_scanner",
        "graphql_probe",
        "inventory_scanner",
        "business_flow_probe"
    ];

    const ALL_KNOWN_METHODS = [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS"
    ];

    const ALL_KNOWN_AUTH_MODES = [
        "none",
        "bearer",
        "api_key",
        "basic",
        "custom"
    ];

    const ALL_KNOWN_CATEGORIES = [
        "API1:2023",
        "API2:2023",
        "API3:2023",
        "API4:2023",
        "API5:2023",
        "API6:2023",
        "API7:2023",
        "API8:2023",
        "API9:2023",
        "API10:2023",
        "GRAPHQL_INTROSPECTION",
        "RECONNAISSANCE",
        "ACTIVE_PROBE"
    ];

    let cachedPolicies = [];
    let cachedActivePolicies = [];
    let currentEditingPolicyId = null;
    let currentActiveTargetsPolicyId = null;
    let currentVersionsPolicyId = null;
    let cachedVersionsList = [];

    function populateCheckboxGrid(containerId, items, selectedSet, inputName) {
        const container = document.getElementById(containerId);
        if (!container) return;
        container.innerHTML = "";
        items.forEach(item => {
            const label = document.createElement("label");
            label.className = "checkbox-item";
            const isChecked = selectedSet ? selectedSet.has(item) : true;
            label.innerHTML = `
                <input type="checkbox" name="${inputName}" value="${escapeHtml(item)}" ${isChecked ? "checked" : ""}>
                <span>${escapeHtml(item)}</span>
            `;
            container.appendChild(label);
        });
    }

    async function loadPolicyMetrics() {
        try {
            const resp = await fetch("/api/admin/policies/metrics");
            if (!resp.ok) return;
            const data = await resp.json();
            if (data.success && data.metrics) {
                const m = data.metrics;
                const setVal = (id, val) => {
                    const el = document.getElementById(id);
                    if (el) el.textContent = val;
                };
                setVal("metric-total-policies", m.total_policies || 0);
                setVal("metric-active-policies", m.active_policies || 0);
                setVal("metric-inactive-policies", m.inactive_policies || 0);
                setVal("metric-total-targets", m.total_targets || 0);
                setVal("metric-active-targets", m.active_targets || 0);
                setVal("metric-expired-targets", m.expired_targets || 0);
                setVal("metric-recently-modified", m.recently_modified || 0);
            }
        } catch (err) {
            console.debug("Failed to load policy metrics", err);
        }
    }

    async function loadPolicies() {
        const tbody = document.getElementById("policies-table-body");
        if (!tbody) return;
        try {
            const resp = await fetch("/api/admin/policies");
            if (!resp.ok) {
                if (resp.status === 401 || resp.status === 403) {
                    tbody.innerHTML = `<tr><td colspan="7" class="loading-cell">Administrator authentication required to manage policies. Sign in as Admin.</td></tr>`;
                }
                return;
            }
            const data = await resp.json();
            cachedPolicies = data.policies || [];
            renderPolicyTable();
        } catch (err) {
            console.error("Failed to load policies", err);
            tbody.innerHTML = `<tr><td colspan="7" class="loading-cell error">Failed to load policy database.</td></tr>`;
        }
    }

    function renderPolicyTable() {
        const tbody = document.getElementById("policies-table-body");
        if (!tbody) return;
        const searchVal = (document.getElementById("policy-search-input")?.value || "").toLowerCase().trim();
        const statusFilter = document.getElementById("policy-status-filter")?.value || "all";

        let filtered = cachedPolicies.filter(p => {
            if (statusFilter === "active" && !p.is_active) return false;
            if (statusFilter === "inactive" && p.is_active) return false;
            if (searchVal) {
                const matchName = (p.name || "").toLowerCase().includes(searchVal);
                const matchDesc = (p.description || "").toLowerCase().includes(searchVal);
                const matchUuid = (p.policy_uuid || "").toLowerCase().includes(searchVal);
                return matchName || matchDesc || matchUuid;
            }
            return true;
        });

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="loading-cell">No matching policies found.</td></tr>`;
            return;
        }

        tbody.innerHTML = filtered.map(p => {
            const statusBadge = p.is_active
                ? `<span class="badge-active">ACTIVE</span>`
                : `<span class="badge-inactive">DISABLED</span>`;
            const cfg = p.config || {};
            const limitsSummary = `${cfg.max_turns || 10} turns / ${cfg.max_requests || 25} reqs`;
            const targetCount = (p.targets || []).length;
            const toggleLabel = p.is_active ? "Disable" : "Enable";
            const toggleClass = p.is_active ? "btn-danger" : "btn-primary";

            return `
                <tr>
                    <td>
                        <strong style="color: var(--accent-cyan); font-size: 0.9rem;">${escapeHtml(p.name)}</strong>
                        <div style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(p.policy_uuid)}</div>
                    </td>
                    <td><small style="color: var(--text-secondary);">${escapeHtml(p.description || "No description")}</small></td>
                    <td><span class="badge-version">v${p.current_version}</span></td>
                    <td><span class="badge-pill">${targetCount} target(s)</span></td>
                    <td><span style="font-family: var(--font-mono); font-size: 0.75rem;">${escapeHtml(limitsSummary)}</span></td>
                    <td>${statusBadge}</td>
                    <td>
                        <div class="policy-action-group">
                            <button class="btn btn-secondary btn-sm" onclick="window.editPolicy(${p.id})">Edit</button>
                            <button class="btn btn-secondary btn-sm" onclick="window.manageTargets(${p.id})">Targets</button>
                            <button class="btn btn-secondary btn-sm" onclick="window.viewVersions(${p.id})">Versions</button>
                            <button class="btn ${toggleClass} btn-sm" onclick="window.togglePolicy(${p.id}, ${p.is_active})">${toggleLabel}</button>
                        </div>
                    </td>
                </tr>
            `;
        }).join("");
    }

    function openCreatePolicyModal() {
        currentEditingPolicyId = null;
        document.getElementById("policy-modal-title").textContent = "Create New Testing Policy";
        document.getElementById("policy-modal-id").value = "";
        document.getElementById("policy-modal-name").value = "";
        document.getElementById("policy-modal-desc").value = "";
        document.getElementById("policy-summary-group").style.display = "none";
        document.getElementById("policy-modal-summary").value = "";

        populateCheckboxGrid("modal-allowed-tools-grid", ALL_KNOWN_TOOLS, new Set(ALL_KNOWN_TOOLS), "pol_tool");
        populateCheckboxGrid("modal-allowed-methods-grid", ALL_KNOWN_METHODS, new Set(ALL_KNOWN_METHODS), "pol_method");
        populateCheckboxGrid("modal-allowed-auth-grid", ALL_KNOWN_AUTH_MODES, new Set(["none", "bearer", "api_key"]), "pol_auth");
        populateCheckboxGrid("modal-allowed-cats-grid", ALL_KNOWN_CATEGORIES, new Set(ALL_KNOWN_CATEGORIES), "pol_cat");

        document.getElementById("policy-modal-max-turns").value = 10;
        document.getElementById("policy-modal-max-requests").value = 25;
        document.getElementById("policy-modal-max-rps").value = 5.0;
        document.getElementById("policy-modal-max-duration").value = 300;
        document.getElementById("policy-modal-max-concurrency").value = 2;
        document.getElementById("policy-modal-max-body").value = 65536;
        document.getElementById("policy-modal-zap-scan").checked = false;

        const errEl = document.getElementById("policy-modal-error");
        errEl.style.display = "none";
        errEl.textContent = "";

        document.getElementById("policy-modal").classList.add("active");
    }

    async function openEditPolicyModal(policyId) {
        currentEditingPolicyId = policyId;
        const policy = cachedPolicies.find(p => p.id === policyId);
        if (!policy) {
            console.error("Policy not found in cache", policyId);
            return;
        }

        document.getElementById("policy-modal-title").textContent = `Edit Policy (v${policy.current_version}) - ${policy.name}`;
        document.getElementById("policy-modal-id").value = policy.id;
        document.getElementById("policy-modal-name").value = policy.name;
        document.getElementById("policy-modal-desc").value = policy.description || "";
        document.getElementById("policy-summary-group").style.display = "block";
        document.getElementById("policy-modal-summary").value = `Update configuration from v${policy.current_version}`;

        const cfg = policy.config || {};
        populateCheckboxGrid("modal-allowed-tools-grid", ALL_KNOWN_TOOLS, new Set(cfg.allowed_tools || []), "pol_tool");
        populateCheckboxGrid("modal-allowed-methods-grid", ALL_KNOWN_METHODS, new Set(cfg.allowed_http_methods || []), "pol_method");
        populateCheckboxGrid("modal-allowed-auth-grid", ALL_KNOWN_AUTH_MODES, new Set(cfg.allowed_auth_modes || []), "pol_auth");
        populateCheckboxGrid("modal-allowed-cats-grid", ALL_KNOWN_CATEGORIES, new Set(cfg.allowed_categories || []), "pol_cat");

        document.getElementById("policy-modal-max-turns").value = cfg.max_turns || 10;
        document.getElementById("policy-modal-max-requests").value = cfg.max_requests || 25;
        document.getElementById("policy-modal-max-rps").value = cfg.max_requests_per_second || 5.0;
        document.getElementById("policy-modal-max-duration").value = cfg.max_assessment_duration_seconds || 300;
        document.getElementById("policy-modal-max-concurrency").value = cfg.max_concurrent_assessments || 2;
        document.getElementById("policy-modal-max-body").value = cfg.max_response_body_bytes || 65536;
        document.getElementById("policy-modal-zap-scan").checked = Boolean(cfg.zap_active_scan_enabled);

        const errEl = document.getElementById("policy-modal-error");
        errEl.style.display = "none";
        errEl.textContent = "";

        document.getElementById("policy-modal").classList.add("active");
    }

    function closePolicyModal() {
        document.getElementById("policy-modal").classList.remove("active");
    }

    async function savePolicy() {
        const errEl = document.getElementById("policy-modal-error");
        errEl.style.display = "none";
        errEl.textContent = "";

        const name = document.getElementById("policy-modal-name").value.trim();
        const description = document.getElementById("policy-modal-desc").value.trim();
        const changeSummary = document.getElementById("policy-modal-summary").value.trim();

        if (!name) {
            errEl.textContent = "Policy name is required.";
            errEl.style.display = "block";
            return;
        }

        const allowedTools = Array.from(document.querySelectorAll('input[name="pol_tool"]:checked')).map(cb => cb.value);
        if (allowedTools.length === 0) {
            errEl.textContent = "At least one assessment tool must be permitted.";
            errEl.style.display = "block";
            return;
        }

        const allowedMethods = Array.from(document.querySelectorAll('input[name="pol_method"]:checked')).map(cb => cb.value);
        if (allowedMethods.length === 0) {
            errEl.textContent = "At least one HTTP method must be permitted.";
            errEl.style.display = "block";
            return;
        }

        const allowedAuth = Array.from(document.querySelectorAll('input[name="pol_auth"]:checked')).map(cb => cb.value);
        if (allowedAuth.length === 0) {
            errEl.textContent = "At least one authentication mode must be permitted.";
            errEl.style.display = "block";
            return;
        }

        const allowedCats = Array.from(document.querySelectorAll('input[name="pol_cat"]:checked')).map(cb => cb.value);
        if (allowedCats.length === 0) {
            errEl.textContent = "At least one OWASP category must be permitted.";
            errEl.style.display = "block";
            return;
        }

        const maxTurns = parseInt(document.getElementById("policy-modal-max-turns").value, 10);
        const maxRequests = parseInt(document.getElementById("policy-modal-max-requests").value, 10);
        const maxRps = parseFloat(document.getElementById("policy-modal-max-rps").value);
        const maxDuration = parseFloat(document.getElementById("policy-modal-max-duration").value);
        const maxConcurrency = parseInt(document.getElementById("policy-modal-max-concurrency").value, 10);
        const maxBody = parseInt(document.getElementById("policy-modal-max-body").value, 10);
        const zapScan = document.getElementById("policy-modal-zap-scan").checked;

        const config = {
            allowed_tools: allowedTools,
            allowed_http_methods: allowedMethods,
            allowed_auth_modes: allowedAuth,
            allowed_categories: allowedCats,
            max_turns: maxTurns,
            max_requests: maxRequests,
            max_requests_per_second: maxRps,
            max_assessment_duration_seconds: maxDuration,
            max_concurrent_assessments: maxConcurrency,
            max_response_body_bytes: maxBody,
            zap_active_scan_enabled: zapScan,
            max_probes_per_endpoint: 5,
        };

        const isEditing = Boolean(currentEditingPolicyId);
        const endpoint = isEditing ? `/api/admin/policies/${currentEditingPolicyId}` : "/api/admin/policies";
        const method = isEditing ? "PUT" : "POST";

        const payload = isEditing ? {
            name: name,
            description: description,
            change_summary: changeSummary || "Configuration updated",
            config: config,
        } : {
            name: name,
            description: description,
            config: config,
        };

        try {
            const resp = await fetch(endpoint, {
                method: method,
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfToken || "",
                },
                body: JSON.stringify(payload),
            });
            const res = await resp.json();
            if (!resp.ok || !res.success) {
                errEl.textContent = res.error || "Operation rejected by server";
                errEl.style.display = "block";
                return;
            }

            closePolicyModal();
            await loadPolicies();
            await loadPolicyMetrics();
            await loadActivePoliciesDropdown();
        } catch (err) {
            console.error("Save policy error", err);
            errEl.textContent = "Network error while saving policy.";
            errEl.style.display = "block";
        }
    }

    async function togglePolicy(policyId, currentIsActive) {
        const action = currentIsActive ? "deactivate" : "activate";
        try {
            const resp = await fetch(`/api/admin/policies/${policyId}/${action}`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfToken || "",
                },
            });
            const data = await resp.json();
            if (!resp.ok || !data.success) {
                alert(`Error: ${data.error || "Action failed"}`);
                return;
            }
            await loadPolicies();
            await loadPolicyMetrics();
            await loadActivePoliciesDropdown();
        } catch (err) {
            console.error("Toggle policy error", err);
        }
    }

    // --- TARGET AUTHORIZATION MANAGEMENT ---

    async function manageTargets(policyId) {
        currentActiveTargetsPolicyId = policyId;
        const policy = cachedPolicies.find(p => p.id === policyId);
        document.getElementById("target-modal-title").textContent = `Authorized Target Whitelist - ${policy ? policy.name : "Policy " + policyId}`;
        document.getElementById("target-modal-policy-id").value = policyId;
        document.getElementById("target-modal-error").style.display = "none";
        document.getElementById("target-modal").classList.add("active");

        await refreshTargetsTable(policyId);
    }

    function closeTargetsModal() {
        document.getElementById("target-modal").classList.remove("active");
        loadPolicies();
        loadPolicyMetrics();
        loadActivePoliciesDropdown();
    }

    async function refreshTargetsTable(policyId) {
        const tbody = document.getElementById("policy-targets-table-body");
        if (!tbody) return;
        try {
            const resp = await fetch(`/api/admin/policies/${policyId}/targets?active_only=0`);
            const data = await resp.json();
            const targets = data.targets || [];
            if (targets.length === 0) {
                tbody.innerHTML = `<tr><td colspan="7" class="loading-cell">No target authorization rules defined.</td></tr>`;
                return;
            }

            const now = Date.now() / 1000;
            tbody.innerHTML = targets.map(t => {
                const isExpired = t.expires_at && now > t.expires_at;
                const statusBadge = !t.is_active
                    ? `<span class="badge-inactive">REVOKED</span>`
                    : (isExpired ? `<span class="badge-expired">EXPIRED</span>` : `<span class="badge-active">ACTIVE</span>`);
                const expiryText = t.expires_at
                    ? new Date(t.expires_at * 1000).toLocaleString()
                    : "Never (Standing)";
                const revokeBtn = t.is_active && !isExpired
                    ? `<button class="btn btn-danger btn-sm" onclick="window.revokeTarget(${t.id})">Revoke</button>`
                    : `<span style="color: var(--text-muted); font-size: 0.75rem;">Inactive</span>`;

                return `
                    <tr>
                        <td><code style="color: var(--accent-cyan); font-weight: bold;">${escapeHtml(t.host_pattern)}</code></td>
                        <td><code>${escapeHtml(t.port_range)}</code></td>
                        <td>${escapeHtml(t.allowed_schemes)}</td>
                        <td><code>${escapeHtml(t.path_prefix)}</code></td>
                        <td><small style="color: var(--text-secondary);">${escapeHtml(expiryText)}</small></td>
                        <td>${statusBadge}</td>
                        <td>${revokeBtn}</td>
                    </tr>
                `;
            }).join("");
        } catch (err) {
            console.error("Failed to load targets", err);
            tbody.innerHTML = `<tr><td colspan="7" class="loading-cell error">Failed to load target authorization list.</td></tr>`;
        }
    }

    async function addTarget() {
        const errEl = document.getElementById("target-modal-error");
        errEl.style.display = "none";
        errEl.textContent = "";

        const policyId = currentActiveTargetsPolicyId;
        const hostPattern = document.getElementById("target-host-pattern").value.trim();
        const portRange = document.getElementById("target-port-range").value.trim() || "*";
        const allowedSchemes = document.getElementById("target-allowed-schemes").value.trim() || "http,https";
        const pathPrefix = document.getElementById("target-path-prefix").value.trim() || "/";
        const expiresHours = parseFloat(document.getElementById("target-expires-hours").value || "0");

        if (!hostPattern) {
            errEl.textContent = "Host pattern is required.";
            errEl.style.display = "block";
            return;
        }

        const expiresAt = expiresHours > 0 ? (Date.now() / 1000) + (expiresHours * 3600) : null;
        const isWildcard = hostPattern.includes("*");

        const payload = {
            host_pattern: hostPattern,
            port_range: portRange,
            allowed_schemes: allowedSchemes,
            path_prefix: pathPrefix,
            is_wildcard: isWildcard,
            expires_at: expiresAt,
            is_active: true,
        };

        try {
            const resp = await fetch(`/api/admin/policies/${policyId}/targets`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfToken || "",
                },
                body: JSON.stringify(payload),
            });
            const data = await resp.json();
            if (!resp.ok || !data.success) {
                errEl.textContent = data.error || "Failed to add target";
                errEl.style.display = "block";
                return;
            }

            document.getElementById("target-host-pattern").value = "";
            document.getElementById("target-expires-hours").value = "0";
            await refreshTargetsTable(policyId);
            await loadPolicyMetrics();
        } catch (err) {
            console.error("Add target error", err);
            errEl.textContent = "Network error adding target.";
            errEl.style.display = "block";
        }
    }

    async function revokeTarget(targetId) {
        showConfirmModal(
            "Revoke Target Authorization",
            "Are you sure you want to revoke this target authorization rule? Any active assessments targeting this scope will be halted immediately.",
            async () => {
                try {
                    const resp = await fetch(`/api/admin/policies/${currentActiveTargetsPolicyId}/targets/${targetId}/revoke`, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "X-CSRF-Token": csrfToken || "",
                        },
                    });
                    const data = await resp.json();
                    if (!resp.ok || !data.success) {
                        showToast(`Error: ${data.error || "Failed to revoke target"}`, "error");
                        return;
                    }
                    showToast("Target authorization revoked successfully", "success");
                    await refreshTargetsTable(currentActiveTargetsPolicyId);
                    await loadPolicyMetrics();
                } catch (err) {
                    console.error("Revoke target error", err);
                    showToast("Network error revoking target.", "error");
                }
            },
            true
        );
    }

    // --- VERSION HISTORY & ROLLBACK ---

    async function viewVersions(policyId) {
        currentVersionsPolicyId = policyId;
        const policy = cachedPolicies.find(p => p.id === policyId);
        document.getElementById("versions-modal-title").textContent = `Version History - ${policy ? policy.name : "Policy " + policyId}`;
        document.getElementById("versions-modal-policy-id").value = policyId;
        document.getElementById("version-config-inspector").textContent = "Click 'Inspect' on any version row to inspect its configuration JSON.";
        document.getElementById("versions-modal-error").style.display = "none";
        document.getElementById("versions-modal").classList.add("active");

        const tbody = document.getElementById("policy-versions-table-body");
        tbody.innerHTML = `<tr><td colspan="6" class="loading-cell">Loading version history...</td></tr>`;

        try {
            const resp = await fetch(`/api/admin/policies/${policyId}/versions`);
            const data = await resp.json();
            cachedVersionsList = data.versions || [];
            if (cachedVersionsList.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="loading-cell">No version records found.</td></tr>`;
                return;
            }

            const currentVer = policy ? policy.current_version : null;
            tbody.innerHTML = cachedVersionsList.map(v => {
                const isCurrent = v.version === currentVer;
                const stateBadge = isCurrent
                    ? `<span class="badge-active">CURRENT ACTIVE</span>`
                    : `<span class="badge-version">HISTORICAL</span>`;
                const dateStr = new Date(v.created_at * 1000).toLocaleString();
                const rollbackBtn = isCurrent
                    ? `<span style="color: var(--text-muted); font-size: 0.75rem;">Active</span>`
                    : `<button class="btn btn-warning btn-sm" onclick="window.rollbackPolicy(${v.version})">Rollback</button>`;

                return `
                    <tr>
                        <td><span class="badge-version">v${v.version}</span></td>
                        <td><small style="color: var(--text-secondary);">${escapeHtml(dateStr)}</small></td>
                        <td><code>User #${v.created_by || "System"}</code></td>
                        <td><small>${escapeHtml(v.change_summary || "No summary")}</small></td>
                        <td>${stateBadge}</td>
                        <td>
                            <div class="policy-action-group">
                                <button class="btn btn-secondary btn-sm" onclick="window.inspectVersionConfig(${v.version})">Inspect</button>
                                ${rollbackBtn}
                            </div>
                        </td>
                    </tr>
                `;
            }).join("");
        } catch (err) {
            console.error("Failed to load versions", err);
            tbody.innerHTML = `<tr><td colspan="6" class="loading-cell error">Failed to load versions.</td></tr>`;
        }
    }

    function inspectVersionConfig(version) {
        const ver = cachedVersionsList.find(v => v.version === version);
        const inspector = document.getElementById("version-config-inspector");
        if (ver && inspector) {
            inspector.textContent = JSON.stringify(ver.config, null, 2);
        }
    }

    async function rollbackPolicy(targetVersion) {
        showConfirmModal(
            "Rollback Policy Version",
            `Are you sure you want to rollback to the configuration from Version ${targetVersion}? This will create a new immutable policy version.`,
            async () => {
                const errEl = document.getElementById("versions-modal-error");
                errEl.style.display = "none";
                try {
                    const resp = await fetch(`/api/admin/policies/${currentVersionsPolicyId}/rollback`, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "X-CSRF-Token": csrfToken || "",
                        },
                        body: JSON.stringify({ target_version: targetVersion }),
                    });
                    const data = await resp.json();
                    if (!resp.ok || !data.success) {
                        errEl.textContent = data.error || "Rollback failed";
                        errEl.style.display = "block";
                        showToast(data.error || "Rollback failed", "error");
                        return;
                    }

                    showToast(`Successfully rolled back to configuration of version ${targetVersion}!`, "success");
                    closeVersionsModal();
                    await loadPolicies();
                    await loadPolicyMetrics();
                    await loadActivePoliciesDropdown();
                } catch (err) {
                    console.error("Rollback error", err);
                    errEl.textContent = "Network error during rollback.";
                    errEl.style.display = "block";
                    showToast("Network error during rollback.", "error");
                }
            },
            true
        );
    }

    function closeVersionsModal() {
        document.getElementById("versions-modal").classList.remove("active");
    }

    // --- ADMINISTRATIVE AUDIT LOG ---

    async function loadAuditLog() {
        const tbody = document.getElementById("audit-log-table-body");
        if (!tbody) return;
        try {
            const resp = await fetch("/api/admin/audit-log?limit=50");
            if (!resp.ok) {
                if (resp.status === 401 || resp.status === 403) {
                    tbody.innerHTML = `<tr><td colspan="6" class="loading-cell">Administrator privileges required to view audit logs.</td></tr>`;
                }
                return;
            }
            const data = await resp.json();
            const logs = data.audit_log || [];
            if (logs.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="loading-cell">No administrative audit events recorded yet.</td></tr>`;
                return;
            }

            tbody.innerHTML = logs.map(l => {
                const dateStr = new Date(l.timestamp * 1000).toLocaleString();
                const statusBadge = l.status === "SUCCESS"
                    ? `<span class="badge-active">SUCCESS</span>`
                    : `<span class="badge-inactive">${escapeHtml(l.status)}</span>`;
                const detailsStr = l.details ? JSON.stringify(l.details) : "{}";

                return `
                    <tr>
                        <td><small style="color: var(--text-secondary); font-family: var(--font-mono);">${escapeHtml(dateStr)}</small></td>
                        <td><code>${escapeHtml(l.username || "User #" + l.user_id)}</code></td>
                        <td><strong style="color: var(--accent-cyan); font-size: 0.78rem;">${escapeHtml(l.action)}</strong></td>
                        <td><span class="badge-pill">${escapeHtml(l.resource_type)} ${escapeHtml(l.resource_id)}</span></td>
                        <td><code style="font-size: 0.72rem; color: var(--text-secondary);">${escapeHtml(detailsStr)}</code></td>
                        <td>${statusBadge}</td>
                    </tr>
                `;
            }).join("");
        } catch (err) {
            console.error("Failed to load audit logs", err);
            tbody.innerHTML = `<tr><td colspan="6" class="loading-cell error">Failed to load audit logs.</td></tr>`;
        }
    }

    // --- ACTIVE POLICIES DROPDOWN & CLIENT-SIDE SCOPE PRE-VALIDATION ---

    async function loadActivePoliciesDropdown() {
        const select = document.getElementById("assessment_policy_id");
        if (!select) return;
        try {
            const resp = await fetch("/api/policies/active");
            if (!resp.ok) return;
            const data = await resp.json();
            cachedActivePolicies = data.policies || [];

            const currentVal = select.value;
            select.innerHTML = `<option value="">Auto-Select Active Policy</option>` + cachedActivePolicies.map(p => {
                const targetCount = (p.targets || []).length;
                return `<option value="${p.id}">${escapeHtml(p.name)} (v${p.current_version}, ${targetCount} targets)</option>`;
            }).join("");

            if (currentVal) select.value = currentVal;
            updateScopeValidationBadge();
        } catch (err) {
            console.debug("Failed to load active policies dropdown", err);
        }
    }

    function validateTargetAgainstPolicy(url, policy) {
        if (!url || !policy) return { valid: false, reason: "No target URL or policy selected" };
        const targets = policy.targets || [];
        if (targets.length === 0) return { valid: false, reason: "Policy defines zero authorized targets" };

        let parsed;
        try {
            parsed = new URL(url);
        } catch (_) {
            return { valid: false, reason: "Invalid target URL format" };
        }

        const scheme = parsed.protocol.replace(":", "").toLowerCase();
        const host = parsed.hostname.toLowerCase();
        const port = parsed.port ? parseInt(parsed.port, 10) : (scheme === "https" ? 443 : 80);
        const path = parsed.pathname || "/";
        const now = Date.now() / 1000;

        for (const t of targets) {
            if (!t.is_active) continue;
            if (t.expires_at && now > t.expires_at) continue;

            const allowedSchemes = (t.allowed_schemes || "http,https").split(",").map(s => s.trim().toLowerCase());
            if (!allowedSchemes.includes(scheme)) continue;

            const pattern = (t.host_pattern || "").trim().toLowerCase();
            let hostMatch = false;
            if (t.is_wildcard || pattern === "*") hostMatch = true;
            else if (pattern === host) hostMatch = true;
            else if (pattern.startsWith("*.") && host.endsWith(pattern.slice(1))) hostMatch = true;

            if (!hostMatch) continue;

            const pRange = String(t.port_range || "*").trim();
            let portMatch = false;
            if (pRange === "*") portMatch = true;
            else if (pRange.includes("-")) {
                const [pMin, pMax] = pRange.split("-").map(x => parseInt(x, 10));
                portMatch = (port >= pMin && port <= pMax);
            } else {
                portMatch = (parseInt(pRange, 10) === port);
            }

            if (!portMatch) continue;

            const pathPrefix = (t.path_prefix || "/").trim();
            if (!path.startsWith(pathPrefix)) continue;

            return { valid: true, reason: `Authorized by rule: ${t.host_pattern}:${t.port_range}` };
        }

        return { valid: false, reason: "Target endpoint does not match any authorized rule in this policy" };
    }

    function updateScopeValidationBadge() {
        const pill = document.getElementById("target-scope-validation-pill");
        if (!pill) return;
        const targetUrl = (document.getElementById("target_url")?.value || "").trim();
        const policySelect = document.getElementById("assessment_policy_id");
        const policyId = policySelect?.value ? parseInt(policySelect.value, 10) : null;

        if (!targetUrl) {
            pill.className = "scope-pill scope-unknown";
            pill.textContent = "Target Scope: Not Specified";
            return;
        }

        // Auto-sync target host into allowed_hosts field so user never has to type it
        try {
            const u = new URL(targetUrl.includes("://") ? targetUrl : "http://" + targetUrl);
            const hostInput = document.getElementById("allowed_hosts");
            if (hostInput && u.hostname) {
                const currentHosts = hostInput.value.split(",").map(h => h.trim()).filter(Boolean);
                if (!currentHosts.includes(u.hostname) && !currentHosts.includes(u.host)) {
                    currentHosts.push(u.host);
                    hostInput.value = currentHosts.join(", ");
                }
            }
        } catch (_) {}

        let policy = null;
        if (policyId) {
            policy = cachedActivePolicies.find(p => p.id === policyId);
        } else if (cachedActivePolicies.length > 0) {
            policy = cachedActivePolicies[0];
        }

        if (!policy) {
            pill.className = "scope-pill scope-unknown";
            pill.textContent = "Target Scope: Auto-Permitted by Active Policy";
            return;
        }

        const res = validateTargetAgainstPolicy(targetUrl, policy);
        if (res.valid) {
            pill.className = "scope-pill scope-valid";
            pill.textContent = `Target Scope: Valid (${policy.name})`;
        } else {
            pill.className = "scope-pill scope-invalid";
            pill.textContent = `Target Scope Violation: ${res.reason}`;
        }
    }

    // Attach Policy Global Window Functions for Inline Event Handlers
    window.editPolicy = openEditPolicyModal;
    window.manageTargets = manageTargets;
    window.viewVersions = viewVersions;
    window.togglePolicy = togglePolicy;
    window.inspectVersionConfig = inspectVersionConfig;
    window.rollbackPolicy = rollbackPolicy;
    window.revokeTarget = revokeTarget;
    window.quickRemoveDomain = quickRemoveDomain;

    // --- Quick Scope & Personal Domain Controller ---
    let quickScopePolicyId = null;

    async function loadQuickScopeStatus() {
        try {
            const resp = await fetch("/api/policies/scope-status");
            if (!resp.ok) return;
            const data = await resp.json();
            if (!data.success || !data.scope_status) return;

            const s = data.scope_status;
            quickScopePolicyId = s.policy_id;

            const pill = document.getElementById("scope-status-pill");
            if (pill) {
                pill.textContent = `Policy: ${s.policy_name} (v${s.current_version})`;
                pill.className = s.is_active ? "badge badge-success" : "badge badge-idle";
            }

            const toggleExt = document.getElementById("toggle-allow-external");
            if (toggleExt) {
                toggleExt.checked = !!s.allow_external_domains;
            }

            const toggleFull = document.getElementById("toggle-full-control");
            if (toggleFull) {
                toggleFull.checked = !!s.full_control_enabled;
            }

            renderQuickAuthorizedDomains(s.active_targets || []);
        } catch (err) {
            console.debug("Failed to load scope status", err);
        }
    }

    function renderQuickAuthorizedDomains(targets) {
        const container = document.getElementById("quick-authorized-domains-container");
        if (!container) return;

        if (!targets || targets.length === 0) {
            container.innerHTML = `<span style="font-size: 0.8rem; color: #64748b; font-style: italic;">No specific domains authorized yet. (External toggle allows any hosted domain when ON).</span>`;
            return;
        }

        container.innerHTML = targets.map(t => {
            const isWildcard = t.host_pattern === "*" || t.is_wildcard === 1;
            const badgeIcon = isWildcard ? "🌐" : "🎯";
            const label = isWildcard ? "* (All External Domains Allowed)" : `${t.host_pattern}${t.port_range && t.port_range !== "*" ? ":" + t.port_range : ""}`;
            return `
                <div class="domain-pill-badge" title="Target ID: ${t.id}">
                    <span>${badgeIcon}</span>
                    <span>${escapeHtml(label)}</span>
                    <span class="remove-btn" onclick="quickRemoveDomain(${t.id})" title="Revoke Authorization">&times;</span>
                </div>
            `;
        }).join("");
    }

    async function handleToggleExternalDomains(e) {
        const enabled = e.target.checked;
        try {
            const resp = await fetch("/api/admin/policies/toggle-external", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfToken || "",
                },
                body: JSON.stringify({
                    enabled: enabled,
                    policy_id: quickScopePolicyId,
                }),
            });
            const data = await resp.json();
            if (!resp.ok || !data.success) {
                e.target.checked = !enabled; // Revert switch on error
                showToast(data.error || "Failed to toggle external domains (Admin login required)", "error");
                return;
            }
            showToast(data.message || (enabled ? "External hosted domain testing enabled!" : "External domain scanning disabled"), "success");
            loadQuickScopeStatus();
            loadPolicies();
            loadPolicyMetrics();
        } catch (err) {
            e.target.checked = !enabled;
            showToast("Failed to communicate with policy server", "error");
        }
    }

    async function handleToggleFullControl(e) {
        const enabled = e.target.checked;
        try {
            const resp = await fetch("/api/admin/policies/toggle-full-control", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfToken || "",
                },
                body: JSON.stringify({
                    enabled: enabled,
                    policy_id: quickScopePolicyId,
                }),
            });
            const data = await resp.json();
            if (!resp.ok || !data.success) {
                e.target.checked = !enabled;
                showToast(data.error || "Failed to toggle full permissions (Admin login required)", "error");
                return;
            }
            showToast(data.message || (enabled ? "Full penetration permissions granted!" : "Reverted to Safe Restricted limits"), "success");
            loadQuickScopeStatus();
            loadPolicies();
            loadPolicyMetrics();
        } catch (err) {
            e.target.checked = !enabled;
            showToast("Failed to communicate with policy server", "error");
        }
    }

    async function handleQuickAddDomain() {
        const input = document.getElementById("quick-domain-input");
        const msg = document.getElementById("quick-domain-msg");
        if (!input) return;

        const val = input.value.trim();
        if (!val) {
            if (msg) {
                msg.textContent = "Please enter a valid domain name or URL (e.g. myapi.com)";
                msg.style.color = "var(--status-red)";
                msg.style.display = "block";
            }
            return;
        }

        try {
            const resp = await fetch("/api/admin/policies/quick-add-domain", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfToken || "",
                },
                body: JSON.stringify({
                    domain: val,
                    policy_id: quickScopePolicyId,
                }),
            });
            const data = await resp.json();
            if (!resp.ok || !data.success) {
                if (msg) {
                    msg.textContent = data.error || "Failed to authorize domain (Admin login required)";
                    msg.style.color = "var(--status-red)";
                    msg.style.display = "block";
                }
                showToast(data.error || "Failed to authorize domain", "error");
                return;
            }

            input.value = "";
            if (msg) {
                msg.textContent = data.message || `Domain '${val}' authorized!`;
                msg.style.color = "var(--status-green)";
                msg.style.display = "block";
                setTimeout(() => { if (msg) msg.style.display = "none"; }, 3500);
            }
            showToast(data.message || "Domain authorized!", "success");
            loadQuickScopeStatus();
            loadPolicies();
            loadPolicyMetrics();
        } catch (err) {
            if (msg) {
                msg.textContent = "Network error connecting to policy API";
                msg.style.color = "var(--status-red)";
                msg.style.display = "block";
            }
            showToast("Network error", "error");
        }
    }

    async function quickRemoveDomain(targetId) {
        if (!confirm("Are you sure you want to revoke authorization for this target domain?")) {
            return;
        }
        try {
            const resp = await fetch("/api/admin/policies/quick-remove-domain", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfToken || "",
                },
                body: JSON.stringify({
                    target_id: targetId,
                    policy_id: quickScopePolicyId,
                }),
            });
            const data = await resp.json();
            if (!resp.ok || !data.success) {
                showToast(data.error || "Failed to revoke domain authorization", "error");
                return;
            }
            showToast(data.message || "Target domain revoked", "success");
            loadQuickScopeStatus();
            loadPolicies();
            loadPolicyMetrics();
        } catch (err) {
            showToast("Failed to communicate with policy server", "error");
        }
    }

    // Attach Event Listeners for Policy UI Controls
    const btnOpenCreate = document.getElementById("btn-open-create-policy");
    if (btnOpenCreate) btnOpenCreate.addEventListener("click", openCreatePolicyModal);

    const btnClosePolicy = document.getElementById("btn-close-policy-modal");
    if (btnClosePolicy) btnClosePolicy.addEventListener("click", closePolicyModal);

    const btnCancelPolicy = document.getElementById("btn-cancel-policy-modal");
    if (btnCancelPolicy) btnCancelPolicy.addEventListener("click", closePolicyModal);

    const btnSavePolicy = document.getElementById("btn-save-policy");
    if (btnSavePolicy) btnSavePolicy.addEventListener("click", savePolicy);

    const btnRefreshPolicies = document.getElementById("btn-refresh-policies");
    if (btnRefreshPolicies) {
        btnRefreshPolicies.addEventListener("click", () => {
            loadPolicies();
            loadPolicyMetrics();
        });
    }

    const policySearchInput = document.getElementById("policy-search-input");
    if (policySearchInput) policySearchInput.addEventListener("input", renderPolicyTable);

    const policyStatusFilter = document.getElementById("policy-status-filter");
    if (policyStatusFilter) policyStatusFilter.addEventListener("change", renderPolicyTable);

    const btnCloseTargetModal = document.getElementById("btn-close-target-modal");
    if (btnCloseTargetModal) btnCloseTargetModal.addEventListener("click", closeTargetsModal);

    const btnDoneTargetModal = document.getElementById("btn-done-target-modal");
    if (btnDoneTargetModal) btnDoneTargetModal.addEventListener("click", closeTargetsModal);

    const btnAddTarget = document.getElementById("btn-add-target");
    if (btnAddTarget) btnAddTarget.addEventListener("click", addTarget);

    const btnCloseVersionsModal = document.getElementById("btn-close-versions-modal");
    if (btnCloseVersionsModal) btnCloseVersionsModal.addEventListener("click", closeVersionsModal);

    const btnDoneVersionsModal = document.getElementById("btn-done-versions-modal");
    if (btnDoneVersionsModal) btnDoneVersionsModal.addEventListener("click", closeVersionsModal);

    const btnRefreshAudit = document.getElementById("btn-refresh-audit");
    if (btnRefreshAudit) btnRefreshAudit.addEventListener("click", loadAuditLog);

    const targetUrlInput = document.getElementById("target_url");
    if (targetUrlInput) targetUrlInput.addEventListener("input", updateScopeValidationBadge);

    const policySelectEl = document.getElementById("assessment_policy_id");
    if (policySelectEl) policySelectEl.addEventListener("change", updateScopeValidationBadge);

    // Quick Scope & Domain Toggle Listeners
    const toggleAllowExt = document.getElementById("toggle-allow-external");
    if (toggleAllowExt) toggleAllowExt.addEventListener("change", handleToggleExternalDomains);

    const toggleFullCtrl = document.getElementById("toggle-full-control");
    if (toggleFullCtrl) toggleFullCtrl.addEventListener("change", handleToggleFullControl);

    const btnQuickAddDomain = document.getElementById("btn-quick-add-domain");
    if (btnQuickAddDomain) btnQuickAddDomain.addEventListener("click", handleQuickAddDomain);

    const quickDomainInput = document.getElementById("quick-domain-input");
    if (quickDomainInput) {
        quickDomainInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                handleQuickAddDomain();
            }
        });
    }

    // Startup
    checkSystemHealth();
    checkAuthStatus();
    loadRecentSessions();
    loadActivePoliciesDropdown();
    loadQuickScopeStatus();
    setInterval(checkSystemHealth, 10000);
});

