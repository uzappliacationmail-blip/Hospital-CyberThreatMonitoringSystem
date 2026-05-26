const ROLE     = document.body.dataset.role || "";
const USERNAME = document.body.dataset.username || "";
let trafficChart, donutChart, simChart;

// ── Boot ────────────────────────────────────────────────────────────────────
window.addEventListener("DOMContentLoaded", () => {
  if (ROLE === "admin") {
    document.getElementById("admin-label").style.display = "";
    document.getElementById("nav-users").style.display   = "";
    document.getElementById("nav-audit").style.display   = "";
    document.getElementById("tb-role-chip").className    = "badge b-admin ms-1";
    document.getElementById("tb-role-chip").style.cssText = "padding:2px 8px;font-size:10px";
  }
  initCharts();
  loadCounts();
  loadSummary();
  loadAlerts();
  updateCommandCenter();
  setInterval(updateClock, 1000); updateClock();
  setInterval(() => { loadCounts(); loadSummary(); loadAlerts(); updateCommandCenter(); }, 30000);
});

// ── Clock ───────────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById("clock").textContent = new Date().toLocaleTimeString("en-GB");
}

// ── Toast ───────────────────────────────────────────────────────────────────
const TICONS = { success:"bi-check-circle-fill", error:"bi-exclamation-circle-fill", info:"bi-info-circle-fill", warn:"bi-exclamation-triangle-fill" };
function toast(msg, type="info") {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.innerHTML = `<i class="bi ${TICONS[type]}"></i><span>${msg}</span>`;
  document.getElementById("toast-wrap").appendChild(el);
  setTimeout(() => { el.style.transition="opacity .3s"; el.style.opacity="0"; setTimeout(()=>el.remove(),300); }, 3400);
}

// ── Navigation ──────────────────────────────────────────────────────────────
const SECTIONS = ["dashboard","predict","alerts","simulate","results","users","audit"];
const META = {
  dashboard: ["Overview","Dashboard"],
  predict:   ["Predict Traffic","Classification"],
  alerts:    ["Anomaly Alerts","Alerts"],
  simulate:  ["KDD Simulation","Simulation"],
  results:   ["Simulation History","Results"],
  users:     ["User Management","Admin"],
  audit:     ["Audit Log","Admin"],
};

function nav(name) {
  SECTIONS.forEach(s => document.getElementById("s-"+s).style.display = s===name?"":"none");
  document.querySelectorAll(".nl").forEach(el => el.classList.remove("active"));
  // highlight matching nav button by onclick content
  document.querySelectorAll(".nl").forEach(el => {
    if (el.getAttribute("onclick") === `nav('${name}')`) el.classList.add("active");
  });
  const [title, crumb] = META[name] || [name, name];
  document.getElementById("pg-title").textContent = title;
  document.getElementById("pg-crumb").textContent = crumb;

  if (name === "alerts")  loadAlerts();
  if (name === "results") loadRuns();
  if (name === "users")   loadUsers();
  if (name === "audit")   loadAudit();
}

// ── Charts ──────────────────────────────────────────────────────────────────
function initCharts() {
  const font = { family:"'Inter',sans-serif", size:11 };
  const tip  = { backgroundColor:"#0f2236", titleColor:"#fff", bodyColor:"rgba(255,255,255,.7)", padding:11, cornerRadius:8 };

  trafficChart = new Chart(document.getElementById("trafficChart"), {
    type:"line",
    data:{ labels:[], datasets:[
      { label:"Normal",  data:[], borderColor:"#06b6c8", backgroundColor:"rgba(6,182,200,.08)",  borderWidth:2, tension:.4, fill:true, pointRadius:3, pointBackgroundColor:"#06b6c8", pointBorderColor:"#fff", pointBorderWidth:2 },
      { label:"Anomaly", data:[], borderColor:"#f43f5e", backgroundColor:"rgba(244,63,94,.07)", borderWidth:2, tension:.4, fill:true, pointRadius:3, pointBackgroundColor:"#f43f5e", pointBorderColor:"#fff", pointBorderWidth:2 }
    ]},
    options:{ responsive:true, interaction:{mode:"index",intersect:false},
      plugins:{ legend:{position:"top",labels:{font,boxWidth:10,padding:14,usePointStyle:true,pointStyle:"circle"}}, tooltip:tip },
      scales:{
        x:{ grid:{display:false}, ticks:{font,color:"#94a3b8"}, border:{display:false} },
        y:{ beginAtZero:true, grid:{color:"#f1f5f9"}, ticks:{font,color:"#94a3b8"}, border:{display:false} }
      }
    }
  });

  donutChart = new Chart(document.getElementById("donutChart"), {
    type:"doughnut",
    data:{ labels:["Normal","Anomaly"], datasets:[{ data:[1,0], backgroundColor:["#06b6c8","#f43f5e"], borderWidth:0, hoverOffset:8, borderRadius:4 }] },
    options:{ responsive:true, cutout:"74%",
      plugins:{ legend:{position:"bottom",labels:{font,padding:16,usePointStyle:true,pointStyle:"circle"}}, tooltip:tip }
    }
  });
}

// ── Counts (stat cards) ─────────────────────────────────────────────────────
async function loadCounts() {
  try {
    const d = await (await fetch("/counts")).json();
    const rate = d.total ? (d.anomaly/d.total*100) : 0;
    document.getElementById("stat-total").textContent   = d.total;
    document.getElementById("stat-normal").textContent  = d.normal;
    document.getElementById("stat-anomaly").textContent = d.anomaly;
    document.getElementById("stat-rate").textContent    = rate.toFixed(1)+"%";
    document.getElementById("trend-normal").innerHTML   = `<i class="bi bi-arrow-up"></i> ${d.normal}`;
    document.getElementById("trend-anomaly").innerHTML  = `<i class="bi bi-exclamation-triangle"></i> ${d.anomaly}`;
    document.getElementById("trend-rate").innerHTML     = `<i class="bi bi-graph-up"></i> ${rate.toFixed(1)}%`;
    document.getElementById("donut-pct").textContent    = rate.toFixed(1)+"%";
    if (donutChart) { donutChart.data.datasets[0].data = [d.normal||1, d.anomaly]; donutChart.update("none"); }
  } catch(e) { console.warn(e); }
}

// ── Summary (line chart) ────────────────────────────────────────────────────
async function loadSummary() {
  try {
    const res = await fetch("/summary");
    if (!res.ok) return;
    const data = await res.json();
    const summary = data.summary || [];
    
    if (!summary.length) {
      // Show empty state
      trafficChart.data.labels = Array.from({length:24}, (_,i) => `${String(i).padStart(2,'0')}:00`);
      trafficChart.data.datasets[0].data = Array(24).fill(0);
      trafficChart.data.datasets[1].data = Array(24).fill(0);
    } else {
      trafficChart.data.labels           = summary.map(r=>r.hour);
      trafficChart.data.datasets[0].data = summary.map(r=>r.normal || 0);
      trafficChart.data.datasets[1].data = summary.map(r=>r.anomaly || 0);
    }
    trafficChart.update("none");
  } catch(e) { console.warn("Summary load error:", e); }
}

// ── Alert rows ──────────────────────────────────────────────────────────────
function alertRows(rows, lim) {
  if (!rows.length) return `<tr><td colspan="7"><div class="empty"><i class="bi bi-shield-check"></i><p>✅ No anomalies detected. Your network is secure.</p></div></td></tr>`;
  
  return rows.slice(0,lim).map(r => {
    // Confidence from API is already 0-100
    const conf   = Math.round(r.confidence);
    const sevCls = conf>=85?"high":"med";
    const sevLbl = conf>=85?"High":"Medium";
    const srcBadge = r.source==="kdd"
      ? `<span class="badge b-kdd"><i class="bi bi-database"></i>KDD</span>`
      : `<span class="badge b-manual"><i class="bi bi-hand-index"></i>Manual</span>`;
    
    // Determine threat type based on features
    let threatType = "Unusual Traffic";
    if (r.alert_type === "kdd_anomaly") {
      threatType = "Suspicious Pattern";
    }
    
    return `<tr id="alert-row-${r.alert_id}" onclick="showAlertDetail(${r.alert_id})" style="cursor:pointer;">
      <td><div class="d-flex align-items-center gap-2"><span class="sev ${sevCls}"></span><span style="font-size:12px;font-weight:600;color:var(--text2)">${sevLbl}</span></div></td>
      <td><span class="mono">#${String(r.alert_id).padStart(4,"0")}</span></td>
      <td>${srcBadge}</td>
      <td><span class="badge b-threat" title="${threatType}"><i class="bi bi-exclamation-triangle-fill"></i>${threatType.split(' ')[0]}</span></td>
      <td>
        <div class="d-flex align-items-center gap-2">
          <div class="conf-track"><div class="conf-fill cf-rose" style="width:${Math.min(conf,100)}%"></div></div>
          <span class="mono">${conf}%</span>
        </div>
      </td>
      <td><span class="mono">${r.timestamp}</span></td>
      <td>
        <button class="btn-ic" title="View Details" onclick="event.stopPropagation(); showAlertDetail(${r.alert_id})" style="color:var(--teal)"><i class="bi bi-info-circle"></i></button>
        <button class="btn-ic" title="Mark as reviewed" onclick="event.stopPropagation(); resolveAlert(${r.alert_id})" style="color:var(--amber)"><i class="bi bi-check-circle"></i></button>
      </td>
    </tr>`;
  }).join("");
}

// Show detailed alert information
async function showAlertDetail(alertId) {
  try {
    const res = await fetch(`/alerts`);
    if (!res.ok) return;
    
    const data = await res.json();
    const alert = data.alerts.find(a => a.alert_id === alertId);
    
    if (!alert) return;
    
    const conf = Math.round(alert.confidence);
    const severity = conf >= 85 ? "HIGH" : conf >= 70 ? "MEDIUM" : "LOW";
    
    // Create detailed view
    const detail = `
    <div style="background: linear-gradient(135deg, var(--bg) 0%, #fafcff 100%); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-top: 15px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
        <div>
          <h3 style="margin: 0; color: var(--text); font-size: 18px;">🔍 Alert Details #${String(alertId).padStart(4,"0")}</h3>
          <p style="margin: 5px 0 0 0; color: var(--muted); font-size: 13px;">${alert.timestamp}</p>
        </div>
        <button onclick="this.closest('tr').remove()" style="background: none; border: none; font-size: 20px; cursor: pointer; color: var(--muted);">✕</button>
      </div>
      
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
        <div style="background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 12px;">
          <div style="font-size: 11px; color: var(--muted); text-transform: uppercase; font-weight: 700; margin-bottom: 5px;">Threat Level</div>
          <div style="font-size: 20px; font-weight: 700; color: ${conf >= 85 ? '#ff006e' : conf >= 70 ? '#f59e0b' : '#10b981'};">${severity}</div>
          <div style="font-size: 12px; color: var(--text2); margin-top: 5px;">Confidence: ${conf}%</div>
        </div>
        
        <div style="background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 12px;">
          <div style="font-size: 11px; color: var(--muted); text-transform: uppercase; font-weight: 700; margin-bottom: 5px;">Detection Type</div>
          <div style="font-size: 14px; font-weight: 700; color: var(--text);">${alert.source === 'kdd' ? '🧪 Simulation' : '👤 Manual'}</div>
          <div style="font-size: 12px; color: var(--text2); margin-top: 5px;">Via ${alert.model_name}</div>
        </div>
      </div>
      
      <div style="background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin-bottom: 15px;">
        <div style="font-size: 11px; color: var(--muted); text-transform: uppercase; font-weight: 700; margin-bottom: 8px;">🌐 Network Traffic</div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 13px;">
          <div>
            <span style="color: var(--muted);">Source IP:</span>
            <div style="font-family: monospace; color: var(--text); font-weight: 600;">${alert.source_ip}</div>
          </div>
          <div>
            <span style="color: var(--muted);">Destination IP:</span>
            <div style="font-family: monospace; color: var(--text); font-weight: 600;">${alert.destination_ip}</div>
          </div>
          <div>
            <span style="color: var(--muted);">Protocol:</span>
            <div style="font-family: monospace; color: var(--text); font-weight: 600; text-transform: uppercase;">${alert.protocol || 'tcp'}</div>
          </div>
          <div>
            <span style="color: var(--muted);">Status:</span>
            <div style="font-family: monospace; color: var(--text); font-weight: 600; text-transform: capitalize;">${alert.status || 'anomaly'}</div>
          </div>
        </div>
      </div>
      
      <div style="background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin-bottom: 15px;">
        <div style="font-size: 11px; color: var(--muted); text-transform: uppercase; font-weight: 700; margin-bottom: 8px;">⚠️ What This Means (Hospital Context)</div>
        <div style="font-size: 13px; color: var(--text2); line-height: 1.6;">
          ${getMeaning(conf, alert.alert_type)}
        </div>
      </div>
      
      <div style="background: linear-gradient(135deg, rgba(0,212,255,0.05), rgba(16,185,129,0.05)); border: 1px solid rgba(0,212,255,0.2); border-radius: 8px; padding: 12px;">
        <div style="font-size: 11px; color: var(--muted); text-transform: uppercase; font-weight: 700; margin-bottom: 8px;">💡 Recommended Action</div>
        <div style="font-size: 13px; color: var(--text); line-height: 1.6;">
          ${getAction(conf, alert.alert_type)}
        </div>
      </div>
    </div>
    `;
    
    // Insert after the table
    const row = document.getElementById(`alert-row-${alertId}`);
    if (!row) return;

    // Find the tbody that contains this row
    const tbody = row.closest("tbody");
    if (!tbody) return;

    // Check if detail row already exists in this tbody
    const existing = tbody.querySelector(".alert-detail-row");
    if (existing) {
      if (Number(existing.dataset.alertId) === alertId) {
        existing.remove();
        return;
      }
      existing.remove();
    }

    const tr = document.createElement("tr");
    tr.className = "alert-detail-row";
    tr.dataset.alertId = alertId;
    tr.innerHTML = `<td colspan="7" style="padding:0;border-bottom:1px solid var(--border);">
      <div style="padding:18px 20px;background:linear-gradient(135deg, var(--bg), rgba(248,250,252,.96));border-radius:0 0 14px 14px;border:1px solid var(--border);border-top:none;">
        ${detail}
      </div>
    </td>`;

    row.insertAdjacentElement("afterend", tr);
    tr.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch(e) {
    console.warn(e);
  }
}

// Provide human-readable meaning for alerts
function getMeaning(confidence, alertType) {
  if (confidence >= 85) {
    return `<strong>CRITICAL THREAT DETECTED</strong><br>This traffic pattern strongly matches known attack signatures. Likely indicators include:
      <ul style="margin: 8px 0 0 20px; padding: 0;">
        <li>Unusual port scanning activity</li>
        <li>Abnormal connection patterns to medical devices</li>
        <li>Suspicious data exfiltration attempts</li>
        <li>Unauthorized access attempts to sensitive systems</li>
      </ul>
      <strong style="color: #ff006e;">Action: IMMEDIATE INVESTIGATION REQUIRED</strong>`;
  } else if (confidence >= 70) {
    return `<strong>SUSPICIOUS ACTIVITY DETECTED</strong><br>This traffic shows characteristics similar to threat patterns. Possible causes:
      <ul style="margin: 8px 0 0 20px; padding: 0;">
        <li>Anomalous connection behavior from medical devices</li>
        <li>Unusual data volume or frequency</li>
        <li>Non-standard protocol usage</li>
        <li>After-hours activity from restricted areas</li>
      </ul>
      <strong style="color: #f59e0b;">Action: MONITOR CLOSELY & INVESTIGATE IF CONTINUES</strong>`;
  } else {
    return `<strong>UNUSUAL PATTERN DETECTED</strong><br>This traffic differs from normal baseline patterns. Likely explanations:
      <ul style="margin: 8px 0 0 20px; padding: 0;">
        <li>New medical device on network</li>
        <li>Software updates or patches being installed</li>
        <li>Scheduled maintenance activities</li>
        <li>Legitimate business operations outside normal patterns</li>
      </ul>
      <strong style="color: #10b981;">Action: MONITOR & VERIFY WITH IT/OPERATIONS</strong>`;
  }
}

// Provide recommended actions for alerts
function getAction(confidence, alertType) {
  if (confidence >= 85) {
    return `
      <strong>🚨 IMMEDIATE STEPS:</strong>
      <ol style="margin: 8px 0 0 20px;">
        <li><strong>Isolate</strong> affected network segment (if critical)</li>
        <li><strong>Notify</strong> Security/IT leadership immediately</li>
        <li><strong>Document</strong> source IP, timestamp, and affected systems</li>
        <li><strong>Check</strong> backup status of critical systems</li>
        <li><strong>Preserve</strong> logs for forensic analysis</li>
        <li><strong>Contact</strong> incident response team</li>
      </ol>
    `;
  } else if (confidence >= 70) {
    return `
      <strong>🔍 INVESTIGATION STEPS:</strong>
      <ol style="margin: 8px 0 0 20px;">
        <li><strong>Identify</strong> source device (IP owner, system type)</li>
        <li><strong>Check</strong> recent device changes or updates</li>
        <li><strong>Review</strong> firewall logs for context</li>
        <li><strong>Contact</strong> system owner to verify legitimacy</li>
        <li><strong>Continue</strong> monitoring for escalation patterns</li>
        <li><strong>Escalate</strong> to security team if pattern continues</li>
      </ol>
    `;
  } else {
    return `
      <strong>📋 VERIFICATION STEPS:</strong>
      <ol style="margin: 8px 0 0 20px;">
        <li><strong>Check</strong> if source IP is known/trusted</li>
        <li><strong>Verify</strong> no recent incidents reported</li>
        <li><strong>Monitor</strong> for pattern recurrence</li>
        <li><strong>Note</strong> in baseline if verified as legitimate</li>
        <li><strong>Continue</strong> normal monitoring</li>
        <li><strong>Mark as reviewed</strong> if no action needed</li>
      </ol>
    `;
  }
}

async function loadAlerts() {
  try {
    const {alerts, count} = await (await fetch("/alerts")).json();
    const badge = document.getElementById("alert-badge");
    badge.textContent = count||""; badge.style.display = count?"inline-block":"none";
    document.getElementById("preview-body").innerHTML = alertRows(alerts, 6);
    const full = document.getElementById("alerts-body");
    if(full) full.innerHTML = alertRows(alerts, 100);
    
    // Update command center with latest alert
    if (alerts.length > 0) {
      const latest = alerts[0];
      const now = new Date();
      const alertTime = new Date(latest.timestamp);
      const diffMin = Math.floor((now - alertTime) / 60000);
      document.getElementById("cc-latest").textContent = diffMin < 1 ? "Just now" : `${diffMin}m ago`;
    }
    
    // Update heatmap and timeline
    updateHeatmap(alerts);
    updateTimeline(alerts);
  } catch(e) { console.warn(e); }
}

// ── Command Center Updates ──────────────────────────────────────────────────
function updateCommandCenter() {
  try {
    const incidents = document.querySelectorAll("tr[id^='alert-row-']").length;
    const threatScore = Math.round((incidents / Math.max(incidents, 10)) * 100);
    
    document.getElementById("cc-incidents").textContent = incidents;
    document.getElementById("cc-threat").textContent = `${Math.min(threatScore, 100)}/100`;
    
    const readyEl = document.getElementById("cc-response");
    if (threatScore > 70) {
      readyEl.className = "cc-status critical";
      readyEl.textContent = "⚠ CRITICAL";
    } else if (threatScore > 40) {
      readyEl.className = "cc-status warning";
      readyEl.textContent = "⚡ ELEVATED";
    } else {
      readyEl.className = "cc-status ready";
      readyEl.textContent = "✓ Ready";
    }
  } catch(e) { console.warn(e); }
}

// ── Threat Heatmap (24 hours) ──────────────────────────────────────────────
function updateHeatmap(alerts) {
  try {
    const heatmapEl = document.getElementById("heatmap-wrap");
    if (!heatmapEl) return;
    
    // Count alerts per hour
    const hourCounts = new Array(24).fill(0);
    alerts.forEach(a => {
      const hour = new Date(a.timestamp).getHours();
      hourCounts[hour]++;
    });
    
    const maxCount = Math.max(...hourCounts, 1);
    const html = hourCounts.map((count, hour) => {
      const intensity = maxCount > 0 ? count / maxCount : 0;
      const colorClass = intensity > 0.7 ? "heat-critical" : intensity > 0.4 ? "heat-warning" : intensity > 0.1 ? "heat-caution" : "heat-safe";
      return `<div class="heat-cell ${colorClass}" title="${String(hour).padStart(2,'0')}:00 — ${count} alert${count!==1?'s':''}" style="opacity:${0.3 + intensity * 0.7}"><span>${String(hour).padStart(2,'0')}</span></div>`;
    }).join("");
    
    heatmapEl.innerHTML = html;
  } catch(e) { console.warn(e); }
}

// ── Response Timeline ──────────────────────────────────────────────────────
function updateTimeline(alerts) {
  try {
    const timelineEl = document.getElementById("timeline-wrap");
    if (!timelineEl) return;
    
    if (!alerts.length) {
      timelineEl.innerHTML = `<div class="timeline-item neutral"><div class="tl-time">—</div><div class="tl-msg">No recent activity</div></div>`;
      return;
    }
    
    const items = alerts.slice(0, 5).map(a => {
      const time = new Date(a.timestamp);
      const conf = Math.round(a.confidence);
      const level = conf >= 85 ? "critical" : conf >= 70 ? "warning" : "info";
      const timeStr = time.toLocaleTimeString("en-GB", {hour:"2-digit", minute:"2-digit"});
      const icon = level === "critical" ? "🔴" : level === "warning" ? "🟠" : "🟡";
      return `<div class="timeline-item ${level}"><div class="tl-icon">${icon}</div><div><div class="tl-time">${timeStr}</div><div class="tl-msg">Alert #${String(a.alert_id).padStart(4,"0")} — ${conf}% confidence</div></div></div>`;
    }).join("");
    
    timelineEl.innerHTML = items;
  } catch(e) { console.warn(e); }
}

async function resolveAlert(alertId) {
  try {
    const res = await fetch(`/alerts/resolve/${alertId}`, { method: "POST" });
    if (res.ok) {
      toast(`✅ Alert #${String(alertId).padStart(4,"0")} marked as resolved.`, "success");
      loadAlerts();
    } else {
      toast("❌ Failed to resolve alert", "error");
    }
  } catch (e) {
    toast("Error: " + e.message, "error");
  }
}

// ── Predict ─────────────────────────────────────────────────────────────────
async function doPredict() {
  const payload = {
    duration:         parseFloat(document.getElementById("f-dur").value)||0,
    protocol_type:    parseInt(document.getElementById("f-proto").value),
    src_bytes:        parseFloat(document.getElementById("f-src").value)||0,
    dst_bytes:        parseFloat(document.getElementById("f-dst").value)||0,
    flag:             parseInt(document.getElementById("f-flag").value)||0,
    land:             parseInt(document.getElementById("f-land").value),
    wrong_fragment:   parseFloat(document.getElementById("f-frag").value)||0,
    urgent:           parseFloat(document.getElementById("f-urg").value)||0,
    hot:              parseFloat(document.getElementById("f-hot").value)||0,
    num_failed_logins:parseFloat(document.getElementById("f-fail").value)||0,
  };
  const btn   = document.getElementById("btn-classify");
  const panel = document.getElementById("res-panel");
  btn.innerHTML = '<i class="bi bi-hourglass-split spin"></i>Classifying…'; btn.disabled = true;
  panel.className = "res-panel";
  panel.innerHTML = `<div class="res-ph"><i class="bi bi-hourglass-split spin" style="font-size:28px;color:var(--teal)"></i>Analysing packet…</div>`;

  try {
    const res  = await fetch("/predict",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    if (res.status===401) { location.href="/login"; return; }
    if (res.status===429) { toast("Rate limit reached. Wait 1 minute.","warn"); panel.innerHTML=`<div class="res-ph"><i class="bi bi-clock-history"></i>Rate limited.</div>`; return; }
    if (res.status===503) { toast("Model not loaded. Run: python fix_model.py","error"); return; }
    const data = await res.json();
    if (data.classification==="anomaly") {
      panel.className="res-panel anomaly";
      panel.innerHTML=`<i class="bi bi-shield-exclamation res-icon"></i><div class="res-label">ANOMALY DETECTED</div><div class="res-conf">${data.confidence}% confidence</div><div class="res-time">${data.timestamp}</div>`;
      toast("Threat detected and logged.","error");
    } else {
      panel.className="res-panel normal";
      panel.innerHTML=`<i class="bi bi-shield-fill-check res-icon"></i><div class="res-label">NORMAL TRAFFIC</div><div class="res-conf">${data.confidence}% confidence</div><div class="res-time">${data.timestamp}</div>`;
      toast("Traffic classified as normal.","success");
    }
    loadCounts(); loadAlerts();
  } catch(e) {
    panel.innerHTML=`<div class="res-ph"><i class="bi bi-exclamation-circle"></i>Request failed.</div>`;
    toast("Prediction failed.","error");
  } finally {
    btn.innerHTML='<i class="bi bi-cpu-fill"></i>Classify Traffic'; btn.disabled=false;
  }
}

function loadSample(type) {
  if (type==="normal") setFields(0.5,0,512,1024,1,0,0,0,1,0);
  else                  setFields(0,0,0,0,2,0,0,0,0,9);
}
function setFields(dur,proto,src,dst,flg,lnd,frg,urg,hot,fail) {
  document.getElementById("f-dur").value=dur; document.getElementById("f-proto").value=proto;
  document.getElementById("f-src").value=src; document.getElementById("f-dst").value=dst;
  document.getElementById("f-flag").value=flg; document.getElementById("f-land").value=lnd;
  document.getElementById("f-frag").value=frg; document.getElementById("f-urg").value=urg;
  document.getElementById("f-hot").value=hot; document.getElementById("f-fail").value=fail;
}

// ── KDD Simulation ──────────────────────────────────────────────────────────
let simFile = null;

function fileSelected(input) {
  simFile = input.files[0];
  document.getElementById("file-name").textContent = simFile ? simFile.name : "";
}

function handleDrop(ev) {
  ev.preventDefault();
  document.getElementById("upload-zone").classList.remove("drag");
  const file = ev.dataTransfer.files[0];
  if (file) { simFile = file; document.getElementById("file-name").textContent = file.name; }
}

function clearSimFile() {
  simFile = null;
  document.getElementById("kdd-file").value = "";
  document.getElementById("file-name").textContent = "";
}

async function runSimulation() {
  const rows   = parseInt(document.getElementById("sim-rows").value)||100;
  const btn    = document.getElementById("btn-sim");
  const progWrap = document.getElementById("sim-progress");
  const progBar  = document.getElementById("sim-prog-bar");
  const progTxt  = document.getElementById("sim-prog-txt");

  btn.innerHTML='<i class="bi bi-hourglass-split spin"></i>Running…'; btn.disabled=true;
  progWrap.style.display="block"; progBar.style.width="10%";
  progTxt.textContent="Preprocessing rows…";
  document.getElementById("sim-result").style.display="none";

  const fd = new FormData();
  fd.append("rows", rows);
  if (simFile) fd.append("file", simFile);

  try {
    progBar.style.width="35%"; progTxt.textContent="Feeding rows to ML model…";
    const res  = await fetch("/simulate",{method:"POST",body:fd});
    progBar.style.width="80%"; progTxt.textContent="Saving results to MySQL…";
    if (res.status===401) { location.href="/login"; return; }
    if (res.status===503) { toast("Model not loaded. Run: python fix_model.py","error"); return; }
    if (!res.ok) { const e=await res.json(); toast(e.detail||"Simulation failed.","error"); return; }
    const data = await res.json();
    progBar.style.width="100%"; progTxt.textContent="Complete.";

    // populate result panel
    setMetric("res-acc",  "bar-acc",  data.accuracy);
    setMetric("res-prec", "bar-prec", data.precision);
    setMetric("res-rec",  "bar-rec",  data.recall);
    setMetric("res-f1",   "bar-f1",   data.f1_score);
    document.getElementById("cm-tp").textContent = data.tp;
    document.getElementById("cm-fp").textContent = data.fp;
    document.getElementById("cm-fn").textContent = data.fn;
    document.getElementById("cm-tn").textContent = data.tn;
    document.getElementById("res-total").textContent  = data.total;
    document.getElementById("res-anom").textContent   = data.anomalies;
    document.getElementById("res-norm").textContent   = data.normals;
    document.getElementById("res-ms").textContent     = data.avg_response_ms+" ms";
    document.getElementById("res-run-id").textContent = `Run #${data.run_id}`;
    document.getElementById("sim-result").style.display="";

    drawSimChart(data.normals, data.anomalies);
    loadCounts(); loadAlerts();
    toast(`Simulation complete — ${data.total} rows processed.`,"success");
    setTimeout(()=>{progWrap.style.display="none";},2000);
  } catch(e) {
    toast("Simulation failed: "+e.message,"error");
    progWrap.style.display="none";
  } finally {
    btn.innerHTML='<i class="bi bi-play-fill"></i>Run Simulation'; btn.disabled=false;
  }
}

function setMetric(valId, barId, pct) {
  document.getElementById(valId).textContent = pct+"%";
  setTimeout(()=>{ document.getElementById(barId).style.width=pct+"%"; }, 100);
}

function drawSimChart(normals, anomalies) {
  if (simChart) simChart.destroy();
  simChart = new Chart(document.getElementById("simChart"), {
    type:"bar",
    data:{
      labels:["Normal","Anomaly"],
      datasets:[{ data:[normals,anomalies], backgroundColor:["rgba(6,182,200,.7)","rgba(244,63,94,.7)"],
        borderColor:["#06b6c8","#f43f5e"], borderWidth:2, borderRadius:6 }]
    },
    options:{
      responsive:true,
      plugins:{ legend:{display:false}, tooltip:{ backgroundColor:"#0f2236", padding:10, cornerRadius:8 } },
      scales:{
        x:{ grid:{display:false}, ticks:{font:{family:"'Inter',sans-serif",size:12}} },
        y:{ beginAtZero:true, grid:{color:"#f1f5f9"}, ticks:{font:{family:"'JetBrains Mono',monospace",size:11}} }
      }
    }
  });
}

// ── Simulation runs history ─────────────────────────────────────────────────
async function loadRuns() {
  try {
    const {runs} = await (await fetch("/kdd/runs")).json();
    document.getElementById("runs-body").innerHTML = runs.length
      ? runs.map(r=>`<tr>
          <td><span class="mono">#${r.id}</span></td>
          <td><span class="badge b-kdd">${r.filename||"synthetic"}</span></td>
          <td><span class="mono">${r.total_rows}</span></td>
          <td><span class="mono" style="color:var(--rose)">${r.anomalies}</span></td>
          <td><strong style="color:var(--green)">${r.accuracy!==null?r.accuracy*100+"%" : "—"}</strong></td>
          <td><strong style="color:var(--amber)">${r.f1!==null?r.f1*100+"%":"—"}</strong></td>
          <td><span class="mono">${r.accuracy!==null?"<2ms":"—"}</span></td>
          <td><span class="mono">${r.started_at}</span></td>
        </tr>`).join("")
      : `<tr><td colspan="8"><div class="empty"><i class="bi bi-bar-chart"></i><p>No simulation runs yet. Go to KDD Simulation to run one.</p></div></td></tr>`;
  } catch(e) { console.warn(e); }
}

// ── Users ───────────────────────────────────────────────────────────────────
async function loadUsers() {
  if (ROLE!=="admin") return;
  try {
    const {users} = await (await fetch("/users")).json();
    document.getElementById("users-body").innerHTML = users.length
      ? users.map(u=>`<tr>
          <td><span class="mono">#${u.id}</span></td>
          <td><strong>${u.username}</strong></td>
          <td><span class="badge ${u.role==="admin"?"b-admin":"b-analyst"}">${u.role}</span></td>
          <td><span class="mono">${u.created_at}</span></td>
          <td>${u.username!==USERNAME
            ?`<button onclick="delUser(${u.id},'${u.username}')" class="btn-ic" style="color:var(--rose);border-color:rgba(244,63,94,.2)"><i class="bi bi-trash3"></i></button>`
            :`<span style="font-size:11px;color:var(--muted)">You</span>`}
          </td></tr>`).join("")
      : `<tr><td colspan="5"><div class="empty"><i class="bi bi-people"></i><p>No users.</p></div></td></tr>`;
  } catch(e) { console.warn(e); }
}

async function addUser() {
  const username = document.getElementById("u-name").value.trim();
  const password = document.getElementById("u-pass").value.trim();
  const role     = document.getElementById("u-role").value;
  if (!username||!password) { toast("Fill in username and password.","error"); return; }
  if (password.length<6)    { toast("Password must be at least 6 characters.","warn"); return; }
  try {
    const res = await fetch("/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username,password,role})});
    if (res.ok) {
      toast(`User '${username}' created.`,"success");
      document.getElementById("u-name").value=""; document.getElementById("u-pass").value="";
      loadUsers();
    } else {
      const e=await res.json(); toast(e.detail||"Error creating user.","error");
    }
  } catch(e) { toast("Request failed.","error"); }
}

async function delUser(id, name) {
  if (!confirm(`Delete user '${name}'? This cannot be undone.`)) return;
  const res = await fetch(`/users/${id}`,{method:"DELETE"});
  if (res.ok) { toast(`User '${name}' deleted.`,"success"); loadUsers(); }
  else toast("Error deleting user.","error");
}

// ── Audit ───────────────────────────────────────────────────────────────────
async function loadAudit() {
  if (ROLE!=="admin") return;
  try {
    const {logs} = await (await fetch("/audit")).json();
    const cls = a => {
      if (a.includes("FAILED")) return "ach-fail";
      if (a==="LOGIN")   return "ach-login";
      if (a==="LOGOUT")  return "ach-logout";
      if (a==="PREDICT") return "ach-predict";
      if (a==="KDD_SIM") return "ach-kdd";
      return "ach-admin";
    };
    document.getElementById("audit-body").innerHTML = logs.length
      ? logs.map(l=>`<tr>
          <td><strong>${l.username}</strong></td>
          <td><span class="ach ${cls(l.action)}">${l.action}</span></td>
          <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${l.detail||""}">${l.detail||"—"}</td>
          <td><span class="mono">${l.ip||"—"}</span></td>
          <td><span class="mono">${l.timestamp}</span></td>
        </tr>`).join("")
      : `<tr><td colspan="5"><div class="empty"><i class="bi bi-journal"></i><p>No audit entries yet.</p></div></td></tr>`;
  } catch(e) { console.warn(e); }
}
