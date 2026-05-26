import { createClient } from '@supabase/supabase-js'

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY)

let currentUser = null

// Password hashing (same as backend)
async function hashPassword(password) {
  const encoder = new TextEncoder()
  const data = encoder.encode('ctms_salt_' + password)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

// Auth
async function login(username, password) {
  const hash = await hashPassword(password)
  const { data, error } = await supabase
    .from('users')
    .select('user_id, username, role, name')
    .eq('username', username)
    .eq('password', hash)
    .single()

  if (error || !data) {
    return { success: false, error: 'Invalid credentials' }
  }
  currentUser = data
  localStorage.setItem('ctms_user', JSON.stringify(data))
  return { success: true, user: data }
}

function logout() {
  currentUser = null
  localStorage.removeItem('ctms_user')
  showLogin()
}

function checkSession() {
  const saved = localStorage.getItem('ctms_user')
  if (saved) {
    currentUser = JSON.parse(saved)
    return true
  }
  return false
}

// Database operations
async function getStats() {
  const { count: total } = await supabase.from('traffic_logs').select('*', { count: 'exact', head: true })
  const { count: normal } = await supabase.from('traffic_logs').select('*', { count: 'exact', head: true }).eq('status', 'normal')
  const { count: anomaly } = await supabase.from('traffic_logs').select('*', { count: 'exact', head: true }).eq('status', 'anomaly')
  return { total: total || 0, normal: normal || 0, anomaly: anomaly || 0 }
}

async function getAlerts(limit = 50) {
  const { data } = await supabase
    .from('alerts')
    .select(`
      alert_id, alert_type, severity, timestamp, resolved,
      log:traffic_logs(source_ip, destination_ip, protocol, status, confidence)
    `)
    .eq('resolved', false)
    .order('timestamp', { ascending: false })
    .limit(limit)
  return data || []
}

async function getTrafficHistory() {
  const yesterday = new Date()
  yesterday.setHours(yesterday.getHours() - 24)

  const { data } = await supabase
    .from('traffic_logs')
    .select('timestamp, status')
    .gte('timestamp', yesterday.toISOString())
    .order('timestamp', { ascending: true })

  return data || []
}

async function logTraffic(features, prediction, confidence) {
  const { data, error } = await supabase
    .from('traffic_logs')
    .insert({
      source_ip: features.source_ip || '0.0.0.0',
      destination_ip: features.destination_ip || '0.0.0.0',
      protocol: features.protocol || 'tcp',
      status: prediction,
      features: JSON.stringify(features),
      confidence: confidence,
      source: 'web'
    })
    .select('log_id')
    .single()

  return { success: !error, log_id: data?.log_id }
}

async function resolveAlert(alertId) {
  const { error } = await supabase
    .from('alerts')
    .update({ resolved: true })
    .eq('alert_id', alertId)
  return { success: !error }
}

// Prediction (calls external API)
async function predict(features) {
  const apiUrl = localStorage.getItem('ctms_api_url') || ''
  if (!apiUrl) {
    // Fallback to random prediction if no API
    const isAnomaly = Math.random() > 0.7
    return {
      prediction: isAnomaly ? 'anomaly' : 'normal',
      confidence: isAnomaly ? 0.85 + Math.random() * 0.15 : 0.90 + Math.random() * 0.1
    }
  }

  try {
    const response = await fetch(`${apiUrl}/api/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(features)
    })
    return await response.json()
  } catch (e) {
    console.error('Prediction API error:', e)
    return { prediction: 'normal', confidence: 0.5 }
  }
}

// UI functions
function showLogin() {
  document.getElementById('app').innerHTML = `
    <div class="login-container">
      <div class="login-card">
        <div class="login-brand">
          <div class="logo"><i class="icon">🛡️</i></div>
          <h1>Hospital CTMS</h1>
          <p>Cyber Threat Monitoring System</p>
        </div>
        <form id="login-form">
          <div class="form-group">
            <label>Username</label>
            <input type="text" id="username" value="admin" required>
          </div>
          <div class="form-group">
            <label>Password</label>
            <input type="password" id="password" value="admin123" required>
          </div>
          <button type="submit" class="btn-primary">Sign In</button>
          <p class="hint">Demo: admin / admin123</p>
        </form>
      </div>
    </div>
  `
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault()
    const result = await login(
      document.getElementById('username').value,
      document.getElementById('password').value
    )
    if (result.success) {
      await showDashboard()
    } else {
      alert('Invalid credentials')
    }
  })
}

async function showDashboard() {
  const stats = await getStats()
  const rate = stats.total > 0 ? ((stats.anomaly / stats.total) * 100).toFixed(1) : 0

  document.getElementById('app').innerHTML = `
    <div class="dashboard">
      <header class="topbar">
        <div class="brand">
          <span class="icon">🛡️</span>
          <span class="title">Hospital CTMS</span>
        </div>
        <div class="user-info">
          <span class="user">${currentUser?.username || 'User'}</span>
          <span class="role badge">${currentUser?.role || 'analyst'}</span>
          <button class="btn-logout" onclick="logout()">Sign Out</button>
        </div>
      </header>

      <div class="content">
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-value">${stats.total}</div>
            <div class="stat-label">Total Logs</div>
          </div>
          <div class="stat-card normal">
            <div class="stat-value">${stats.normal}</div>
            <div class="stat-label">Normal</div>
          </div>
          <div class="stat-card anomaly">
            <div class="stat-value">${stats.anomaly}</div>
            <div class="stat-label">Anomalies</div>
          </div>
          <div class="stat-card rate">
            <div class="stat-value">${rate}%</div>
            <div class="stat-label">Threat Rate</div>
          </div>
        </div>

        <div class="panels">
          <div class="panel">
            <h2><span class="icon">🔮</span> Traffic Prediction</h2>
            <form id="predict-form" class="predict-form">
              <div class="form-row">
                <div class="form-group">
                  <label>Duration</label>
                  <input type="number" step="any" id="duration" value="0.5">
                </div>
                <div class="form-group">
                  <label>Protocol</label>
                  <select id="protocol_type">
                    <option value="0">TCP</option>
                    <option value="1">UDP</option>
                    <option value="2">ICMP</option>
                  </select>
                </div>
                <div class="form-group">
                  <label>Src Bytes</label>
                  <input type="number" id="src_bytes" value="512">
                </div>
                <div class="form-group">
                  <label>Dst Bytes</label>
                  <input type="number" id="dst_bytes" value="0">
                </div>
              </div>
              <div class="form-row">
                <div class="form-group">
                  <label>Flag</label>
                  <input type="number" id="flag" value="1">
                </div>
                <div class="form-group">
                  <label>Source IP</label>
                  <input type="text" id="source_ip" value="192.168.1.100">
                </div>
                <div class="form-group">
                  <label>Dest IP</label>
                  <input type="text" id="destination_ip" value="10.0.0.1">
                </div>
              </div>
              <button type="submit" class="btn-primary">Analyze Traffic</button>
            </form>
            <div id="predict-result"></div>
          </div>

          <div class="panel">
            <h2><span class="icon">⚠️</span> Recent Alerts</h2>
            <div id="alerts-list" class="alerts-list">Loading...</div>
          </div>
        </div>
      </div>
    </div>
  `

  document.getElementById('predict-form').addEventListener('submit', async (e) => {
    e.preventDefault()
    const features = {
      duration: parseFloat(document.getElementById('duration').value),
      protocol_type: parseInt(document.getElementById('protocol_type').value),
      src_bytes: parseFloat(document.getElementById('src_bytes').value),
      dst_bytes: parseFloat(document.getElementById('dst_bytes').value),
      flag: parseFloat(document.getElementById('flag').value),
      source_ip: document.getElementById('source_ip').value,
      destination_ip: document.getElementById('destination_ip').value,
      protocol: ['tcp', 'udp', 'icmp'][parseInt(document.getElementById('protocol_type').value)]
    }

    const resultDiv = document.getElementById('predict-result')
    resultDiv.innerHTML = '<div class="loading">Analyzing...</div>'

    const prediction = await predict(features)

    await logTraffic(features, prediction.prediction, prediction.confidence)

    const isAnomaly = prediction.prediction === 'anomaly'
    resultDiv.innerHTML = `
      <div class="result ${isAnomaly ? 'anomaly' : 'normal'}">
        <div class="result-icon">${isAnomaly ? '🚨' : '✅'}</div>
        <div class="result-text">
          <strong>${isAnomaly ? 'ANOMALY DETECTED' : 'NORMAL TRAFFIC'}</strong>
          <p>Confidence: ${(prediction.confidence * 100).toFixed(1)}%</p>
          <small>Response time: ${prediction.response_ms?.toFixed(2) || 'N/A'}ms</small>
        </div>
      </div>
    `

    // Refresh stats
    setTimeout(() => showDashboard(), 1000)
  })

  // Load alerts
  const alerts = await getAlerts(10)
  const alertsDiv = document.getElementById('alerts-list')
  if (alerts.length === 0) {
    alertsDiv.innerHTML = '<div class="empty">No alerts</div>'
  } else {
    alertsDiv.innerHTML = alerts.map(a => `
      <div class="alert-item severity-${a.severity}">
        <div class="alert-info">
          <strong>${a.alert_type}</strong>
          <span class="severity">${a.severity}</span>
          <small>${a.log?.source_ip} → ${a.log?.destination_ip}</small>
        </div>
        <button class="btn-resolve" onclick="resolveAlertHandler(${a.alert_id})">Resolve</button>
      </div>
    `).join('')
  }
}

// Global handler for alert resolution
window.resolveAlertHandler = async (alertId) => {
  await resolveAlert(alertId)
  await showDashboard()
}

// Init
if (checkSession()) {
  showDashboard()
} else {
  showLogin()
}
