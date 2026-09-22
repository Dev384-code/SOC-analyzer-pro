// Sentryline Security Log Analyzer - Interactive SOC Operations Engine
document.documentElement.dataset.analyzerReady = 'true';

// 1. Interactive Alert Triage Status Handler
window.updateAlertStatus = async function(alertId, newStatus) {
  try {
    const res = await fetch('/api/alert/' + encodeURIComponent(alertId) + '/status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      const row = document.querySelector(`.alert-row-item[data-alert-id="${alertId}"]`) ||
                  document.querySelector(`select[data-alert-id="${alertId}"]`)?.closest('tr');
      if (row) {
        row.setAttribute('data-status', newStatus);
        row.dataset.status = newStatus;
        // Visual feedback
        const select = row.querySelector('.triage-select');
        if (select) {
          select.className = `triage-select status-${newStatus}`;
        }
      }
      if (window.applyAlertFilters) {
        window.applyAlertFilters();
      }
    } else {
      alert('Failed to update status: ' + (data.error || 'Server error'));
    }
  } catch (err) {
    console.error('Error updating triage status:', err);
    alert('Network error while updating alert triage status.');
  }
};

// 2. Incident Report Filtering and Real-time Search
document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('alert-search');
  const severityFilter = document.getElementById('severity-filter');
  const statusFilter = document.getElementById('status-filter');
  const alertRows = document.querySelectorAll('.alert-row-item');
  const countBadge = document.getElementById('visible-count');

  window.applyAlertFilters = function() {
    if (!alertRows.length) return;
    const query = (searchInput ? searchInput.value : '').trim().toLowerCase();
    const severity = (severityFilter ? severityFilter.value : 'all').toLowerCase();
    const status = (statusFilter ? statusFilter.value : 'all').toLowerCase();

    let visibleCount = 0;
    alertRows.forEach(row => {
      const rowText = (row.getAttribute('data-search') || '').toLowerCase();
      const rowSeverity = (row.getAttribute('data-severity') || '').toLowerCase();
      const rowStatus = (row.getAttribute('data-status') || 'open').toLowerCase();

      const matchesQuery = !query || rowText.includes(query);
      const matchesSeverity = severity === 'all' || rowSeverity === severity;
      const matchesStatus = status === 'all' || rowStatus === status;

      if (matchesQuery && matchesSeverity && matchesStatus) {
        row.style.display = '';
        visibleCount++;
      } else {
        row.style.display = 'none';
      }
    });

    if (countBadge) {
      countBadge.textContent = `${visibleCount} of ${alertRows.length} displayed`;
    }
  };

  if (searchInput) searchInput.addEventListener('input', window.applyAlertFilters);
  if (severityFilter) severityFilter.addEventListener('change', window.applyAlertFilters);
  if (statusFilter) statusFilter.addEventListener('change', window.applyAlertFilters);

  // Initialize triage select classes on load
  document.querySelectorAll('.triage-select').forEach(select => {
    select.className = `triage-select status-${select.value}`;
  });

  // 3. Attack Kill-Chain Visualizer (for Dashboard)
  const killChainContainer = document.getElementById('attack-killchain');
  if (killChainContainer) {
    renderKillChain(killChainContainer);
  }
});

function renderKillChain(container) {
  fetch('/api/results')
    .then(r => r.json())
    .then(result => {
      const alerts = result.alerts || [];
      const stages = [
        { id: 'recon', name: 'Recon & Scan', tactic: 'Discovery', tech: ['T1046'], match: ['network_scan'] },
        { id: 'initial', name: 'Initial Access', tactic: 'Initial Access', tech: ['T1190', 'T1078'], match: ['web_attack', 'unusual_time', 'country_change'] },
        { id: 'credential', name: 'Credential Access', tactic: 'Credential Access', tech: ['T1110'], match: ['brute_force', 'brute_force_escalated', 'account_takeover'] },
        { id: 'execution', name: 'Execution & PrivEsc', tactic: 'Privilege Escalation', tech: ['T1548', 'T1218', 'T1105'], match: ['privilege_escalation', 'lolbin_execution', 'post_auth_download_execute'] },
        { id: 'c2', name: 'Command & Control', tactic: 'C2', tech: ['T1071'], match: ['c2_beaconing', 'suspicious_ip'] },
        { id: 'exfil', name: 'Exfiltration', tactic: 'Exfiltration', tech: ['T1041'], match: ['data_exfiltration'] }
      ];

      let html = '<div class="killchain-track">';
      stages.forEach((stage, idx) => {
        const stageAlerts = alerts.filter(a => stage.match.includes(a.type));
        const count = stageAlerts.length;
        const activeClass = count > 0 ? 'active' : 'inactive';
        const highestSeverity = stageAlerts.find(a => a.severity === 'critical') ? 'critical' :
                                stageAlerts.find(a => a.severity === 'high') ? 'high' :
                                stageAlerts.find(a => a.severity === 'medium') ? 'medium' : 'low';

        html += `
          <div class="killchain-node ${activeClass} ${count > 0 ? highestSeverity : ''}">
            <div class="node-badge">0${idx + 1}</div>
            <div class="node-body">
              <span class="node-tactic">${stage.tactic}</span>
              <strong>${stage.name}</strong>
              <div class="node-meta">
                <span class="tech-tag">${stage.tech.join(', ')}</span>
                ${count > 0 ? `<b class="hit-count">${count} signal${count > 1 ? 's' : ''}</b>` : '<span class="muted">No alerts</span>'}
              </div>
            </div>
            ${idx < stages.length - 1 ? '<div class="node-connector"></div>' : ''}
          </div>
        `;
      });
      html += '</div>';

      container.innerHTML = html;
    })
    .catch(err => {
      console.warn('Could not render killchain:', err);
    });
}
