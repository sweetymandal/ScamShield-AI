/* ==========================================================================
   ScamShield AI - Interactive Frontend Controller
   ========================================================================== */

let currentInputMode = 'text';
let currentHistoryData = [];

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    loadDemoSamples();
    loadScanHistory();
});

/* -------------------------------------------------------------------------- */
/* 1. Navigation & Tab Switching                                              */
/* -------------------------------------------------------------------------- */
function initNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            navButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const targetSectionId = btn.getAttribute('data-target');
            document.querySelectorAll('.view-section').forEach(sec => {
                sec.classList.remove('active');
            });
            document.getElementById(targetSectionId).classList.add('active');

            if (targetSectionId === 'history-section') {
                loadScanHistory();
            }
        });
    });
}

function switchInputMode(mode) {
    currentInputMode = mode;
    const tabText = document.getElementById('tab-text');
    const tabUrl = document.getElementById('tab-url');
    const groupText = document.getElementById('group-text');
    const groupUrl = document.getElementById('group-url');

    if (mode === 'text') {
        tabText.classList.add('active');
        tabUrl.classList.remove('active');
        groupText.classList.remove('hidden');
        groupUrl.classList.add('hidden');
    } else {
        tabUrl.classList.add('active');
        tabText.classList.remove('active');
        groupUrl.classList.remove('hidden');
        groupText.classList.add('hidden');
    }
}

/* -------------------------------------------------------------------------- */
/* 2. Demo Preset Chips for Instant Hackathon Testing                        */
/* -------------------------------------------------------------------------- */
async function loadDemoSamples() {
    try {
        const resp = await fetch('/api/samples');
        const res = await resp.json();
        if (res.status === 'success' && res.data) {
            const container = document.getElementById('sample-chips');
            container.innerHTML = '';
            res.data.forEach(sample => {
                const chip = document.createElement('button');
                chip.className = 'chip-btn';
                chip.innerHTML = `<i class="${sample.type === 'url' ? 'fa-solid fa-link' : 'fa-solid fa-envelope'}"></i> ${sample.title}`;
                chip.onclick = () => fillSampleInput(sample.type, sample.content);
                container.appendChild(chip);
            });
        }
    } catch (err) {
        console.error('Error fetching sample chips:', err);
    }
}

function fillSampleInput(type, content) {
    switchInputMode(type);
    if (type === 'text') {
        document.getElementById('text-input').value = content;
    } else {
        document.getElementById('url-input').value = content;
    }
    // Scroll to input form
    document.querySelector('.analyzer-card').scrollIntoView({ behavior: 'smooth' });
}

function clearInput() {
    document.getElementById('text-input').value = '';
    document.getElementById('url-input').value = '';
    document.getElementById('results-card').classList.add('hidden');
}

/* -------------------------------------------------------------------------- */
/* 3. Submit Scan & Render Analysis                                           */
/* -------------------------------------------------------------------------- */
async function handleScanSubmit(event) {
    event.preventDefault();

    const inputContent = currentInputMode === 'text' 
        ? document.getElementById('text-input').value.trim() 
        : document.getElementById('url-input').value.trim();

    if (!inputContent) {
        alert(currentInputMode === 'text' ? 'Please paste message or email text.' : 'Please enter a web URL.');
        return;
    }

    setLoadingState(true);

    try {
        const resp = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                type: currentInputMode,
                content: inputContent
            })
        });

        const res = await resp.json();
        if (res.status === 'success') {
            renderAnalysisResults(res.data);
        } else {
            alert('Analysis Error: ' + (res.message || 'Server error occurred.'));
        }
    } catch (err) {
        console.error('Fetch error:', err);
        alert('Could not connect to backend server. Make sure Flask app is running!');
    } finally {
        setLoadingState(false);
    }
}

function setLoadingState(isLoading) {
    const btnText = document.getElementById('btn-text');
    const btnSpinner = document.getElementById('btn-spinner');
    const analyzeBtn = document.getElementById('analyze-btn');

    if (isLoading) {
        btnText.classList.add('hidden');
        btnSpinner.classList.remove('hidden');
        analyzeBtn.disabled = true;
    } else {
        btnText.classList.remove('hidden');
        btnSpinner.classList.add('hidden');
        analyzeBtn.disabled = false;
    }
}

function renderAnalysisResults(scanData) {
    const resultsCard = document.getElementById('results-card');
    resultsCard.classList.remove('hidden');

    // Badge type
    const badge = document.getElementById('result-type-badge');
    badge.innerText = scanData.scan_type.toUpperCase() + ' SCAN';

    // Summary text
    document.getElementById('result-summary-text').innerText = scanData.summary;

    // Quote preview
    document.getElementById('preview-text-content').innerText = scanData.input_content;

    // Update gauge meter score & color
    updateGaugeMeter(scanData.risk_score, scanData.risk_level);

    // Render Threat Explanations
    const threatContainer = document.getElementById('threat-list-container');
    threatContainer.innerHTML = '';
    
    if (scanData.explanations && scanData.explanations.length > 0) {
        scanData.explanations.forEach(exp => {
            const item = document.createElement('div');
            item.className = scanData.risk_score <= 20 ? 'threat-item safe-item' : 'threat-item';
            item.innerHTML = `<i class="${scanData.risk_score <= 20 ? 'fa-solid fa-circle-check' : 'fa-solid fa-triangle-exclamation'}"></i> ${escapeHtml(exp)}`;
            threatContainer.appendChild(item);
        });
    }

    // Render Recommendations
    const recContainer = document.getElementById('rec-list-container');
    recContainer.innerHTML = '';
    if (scanData.recommendations && scanData.recommendations.length > 0) {
        scanData.recommendations.forEach(rec => {
            const li = document.createElement('li');
            li.innerHTML = `<i class="fa-solid fa-shield-check"></i> <span>${escapeHtml(rec)}</span>`;
            recContainer.appendChild(li);
        });
    }

    // Smooth Scroll down to results
    resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function updateGaugeMeter(score, riskLevel) {
    const scoreNum = document.getElementById('score-num');
    const gaugeCircle = document.getElementById('gauge-circle');
    const riskBadge = document.getElementById('risk-level-badge');

    // Animate score counter
    animateNumber(scoreNum, 0, score, 800);

    // SVG stroke calculations: Circumference = 2 * PI * 70 = ~439.8
    const circumference = 440;
    const offset = circumference - (score / 100) * circumference;
    gaugeCircle.style.strokeDashoffset = offset;

    // Risk badge color and text
    riskBadge.innerText = riskLevel;
    
    let colorHex = '#10b981'; // Safe green
    if (riskLevel === 'LOW RISK') {
        colorHex = '#3b82f6';
    } else if (riskLevel === 'MODERATE RISK') {
        colorHex = '#f59e0b';
    } else if (riskLevel === 'HIGH RISK') {
        colorHex = '#ef4444';
    }

    gaugeCircle.style.stroke = colorHex;
    riskBadge.style.backgroundColor = colorHex;
    riskBadge.style.boxShadow = `0 0 12px ${colorHex}66`;
}

function animateNumber(element, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        element.innerText = Math.floor(progress * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

/* -------------------------------------------------------------------------- */
/* 4. Scan History Operations                                                 */
/* -------------------------------------------------------------------------- */
async function loadScanHistory() {
    try {
        const resp = await fetch('/api/history');
        const res = await resp.json();
        if (res.status === 'success') {
            currentHistoryData = res.data || [];
            renderHistoryCards(currentHistoryData);
        }
    } catch (err) {
        console.error('Error fetching history:', err);
    }
}

function renderHistoryCards(items) {
    const container = document.getElementById('history-cards-container');
    container.innerHTML = '';

    if (!items || items.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-folder-open empty-icon"></i>
                <p>No scan history recorded yet. Run a threat analysis to start logging results!</p>
            </div>
        `;
        return;
    }

    items.forEach(item => {
        const card = document.createElement('div');
        card.className = 'history-card';
        
        let colorClass = '#10b981';
        if (item.risk_level === 'LOW RISK') colorClass = '#3b82f6';
        if (item.risk_level === 'MODERATE RISK') colorClass = '#f59e0b';
        if (item.risk_level === 'HIGH RISK') colorClass = '#ef4444';

        const formattedDate = new Date(item.created_at).toLocaleString();

        card.innerHTML = `
            <div class="h-card-top">
                <span class="badge badge-neutral">${item.scan_type.toUpperCase()}</span>
                <span class="h-card-score" style="color: ${colorClass};">${item.risk_score} / 100</span>
            </div>
            <div class="h-card-content">
                <strong>"${escapeHtml(item.input_content)}"</strong>
            </div>
            <div class="h-card-footer">
                <span><i class="fa-regular fa-clock"></i> ${formattedDate}</span>
                <button class="h-delete-btn" onclick="deleteHistoryItem(${item.id})" title="Delete scan record">
                    <i class="fa-solid fa-trash-can"></i>
                </button>
            </div>
        `;
        container.appendChild(card);
    });
}

function filterHistory() {
    const query = document.getElementById('history-search').value.toLowerCase().trim();
    const typeFilter = document.getElementById('history-filter-type').value;

    const filtered = currentHistoryData.filter(item => {
        const matchesQuery = !query || item.input_content.toLowerCase().includes(query) || item.summary.toLowerCase().includes(query);
        const matchesType = typeFilter === 'all' || item.scan_type === typeFilter;
        return matchesQuery && matchesType;
    });

    renderHistoryCards(filtered);
}

async function deleteHistoryItem(id) {
    if (!confirm('Are you sure you want to delete this scan log?')) return;
    try {
        const resp = await fetch(`/api/history/${id}`, { method: 'DELETE' });
        const res = await resp.json();
        if (res.status === 'success') {
            loadScanHistory();
        }
    } catch (err) {
        console.error('Delete scan failed:', err);
    }
}

async function confirmClearHistory() {
    if (!confirm('Are you sure you want to clear ALL scan history records?')) return;
    try {
        const resp = await fetch('/api/history', { method: 'DELETE' });
        const res = await resp.json();
        if (res.status === 'success') {
            loadScanHistory();
        }
    } catch (err) {
        console.error('Clear history failed:', err);
    }
}

function escapeHtml(str) {
    return str.replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
}
