const API_BASE = "http://127.0.0.1:8000";

async function fetchStats() {
    const res = await fetch(`${API_BASE}/stats`);
    return res.json();
}

async function fetchLogs() {
    const res = await fetch(`${API_BASE}/logs`);
    return res.json();
}

async function fetchAlerts() {
    const res = await fetch(`${API_BASE}/alerts`);
    return res.json();
}
async function fetchGeoEvents() {
    const res = await fetch(`${API_BASE}/geo-events`);
    return res.json();
}

