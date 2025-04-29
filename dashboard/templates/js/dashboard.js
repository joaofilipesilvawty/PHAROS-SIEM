// Configurações globais
const CONFIG = {
    updateInterval: 30000, // 30 segundos
    maxAlerts: 100,
    timeRanges: {
        '1h': 3600000,
        '24h': 86400000,
        '7d': 604800000,
        '30d': 2592000000
    }
};

// Estado global
let state = {
    currentTimeRange: '24h',
    charts: {},
    lastUpdate: null,
    alertCount: 0
};

// Initialize AOS
AOS.init({
    duration: 800,
    easing: 'ease-in-out',
    once: true,
    mirror: false
});

// Chart.js Global Configuration
Chart.defaults.color = '#858796';
Chart.defaults.font.family = "'Nunito', '-apple-system', 'system-ui', sans-serif";

// Chart Type Configurations
const chartTypes = {
    alerts: {
        bar: {
            type: 'bar',
            options: {
                scales: {
                    y: { beginAtZero: true }
                }
            }
        },
        pie: {
            type: 'pie',
            options: {
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        },
        line: {
            type: 'line',
            options: {
                tension: 0.4
            }
        }
    },
    logins: {
        line: {
            type: 'line',
            options: {
                tension: 0.4
            }
        },
        area: {
            type: 'line',
            options: {
                fill: true,
                tension: 0.4
            }
        }
    }
};

// Inicialização
document.addEventListener('DOMContentLoaded', function () {
    initializeDashboard();
    setupEventListeners();
    updateDashboard();
    setInterval(updateDashboard, CONFIG.updateInterval);
});

// Funções de inicialização
function initializeDashboard() {
    // Inicializar gráficos
    initializeCharts();

    // Configurar seletor de período
    setupTimeRangeSelector();

    // Configurar notificações
    setupNotifications();

    // Configurar sidebar
    setupSidebar();
}

function setupEventListeners() {
    // Eventos do seletor de período
    document.querySelectorAll('[data-range]').forEach(item => {
        item.addEventListener('click', e => {
            e.preventDefault();
            const range = e.target.dataset.range;
            if (range === 'custom') {
                showCustomDateRangePicker();
            } else {
                updateTimeRange(range);
            }
        });
    });

    // Eventos de notificação
    document.getElementById('alertCount').addEventListener('click', () => {
        showAlertsModal();
    });
}

// Funções de atualização
async function updateDashboard() {
    try {
        showLoading();

        const [alerts, metrics] = await Promise.all([
            fetchAlerts(),
            fetchMetrics()
        ]);

        updateStatistics(alerts, metrics);
        updateCharts(alerts, metrics);
        updateAlertsTable(alerts);
        updateAlertCount(alerts);

        state.lastUpdate = new Date();
        updateLastUpdateTime();

        hideLoading();
    } catch (error) {
        console.error('Erro ao atualizar dashboard:', error);
        showError('Erro ao atualizar dados do dashboard');
        hideLoading();
    }
}

async function fetchAlerts() {
    const response = await fetch(`/alerts?timeRange=${state.currentTimeRange}`);
    if (!response.ok) throw new Error('Erro ao buscar alertas');
    return response.json();
}

async function fetchMetrics() {
    const response = await fetch(`/metrics?timeRange=${state.currentTimeRange}`);
    if (!response.ok) throw new Error('Erro ao buscar métricas');
    return response.json();
}

// Funções de atualização de UI
function updateStatistics(alerts, metrics) {
    // Alertas hoje
    const todayAlerts = alerts.filter(alert => {
        const alertDate = new Date(alert.created_at);
        const today = new Date();
        return alertDate.toDateString() === today.toDateString();
    });
    document.getElementById('alertsToday').textContent = formatNumber(todayAlerts.length);

    // Métricas de login
    const loginMetrics = metrics.find(m => m.name === 'login_attempts');
    if (loginMetrics) {
        document.getElementById('successfulLogins').textContent = formatNumber(loginMetrics.successful || 0);
        document.getElementById('failedLogins').textContent = formatNumber(loginMetrics.failed || 0);
    }

    // Transações suspeitas
    const suspiciousTransactions = alerts.filter(alert =>
        alert.type === 'suspicious_transaction'
    ).length;
    document.getElementById('suspiciousTransactions').textContent = formatNumber(suspiciousTransactions);
}

function updateCharts(alerts, metrics) {
    updateAlertsByTypeChart(alerts);
    updateLoginAttemptsChart(metrics);
    updateTrendChart(alerts, metrics);
}

function updateAlertsByTypeChart(alerts) {
    const alertTypes = {};
    alerts.forEach(alert => {
        alertTypes[alert.type] = (alertTypes[alert.type] || 0) + 1;
    });

    if (state.charts.alertsByType) {
        state.charts.alertsByType.destroy();
    }

    state.charts.alertsByType = new Chart(document.getElementById('alertsByTypeChart'), {
        type: 'pie',
        data: {
            labels: Object.keys(alertTypes),
            datasets: [{
                data: Object.values(alertTypes),
                backgroundColor: [
                    '#3498db',
                    '#2ecc71',
                    '#f1c40f',
                    '#e74c3c',
                    '#9b59b6',
                    '#1abc9c'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

function updateLoginAttemptsChart(metrics) {
    const loginMetrics = metrics.find(m => m.name === 'login_attempts');
    if (!loginMetrics) return;

    if (state.charts.loginAttempts) {
        state.charts.loginAttempts.destroy();
    }

    state.charts.loginAttempts = new Chart(document.getElementById('loginAttemptsChart'), {
        type: 'line',
        data: {
            labels: ['Última hora', 'Últimas 24h', 'Última semana'],
            datasets: [{
                label: 'Sucesso',
                data: [
                    loginMetrics.last_hour?.successful || 0,
                    loginMetrics.last_24h?.successful || 0,
                    loginMetrics.last_week?.successful || 0
                ],
                borderColor: '#2ecc71',
                backgroundColor: 'rgba(46, 204, 113, 0.1)',
                tension: 0.1,
                fill: true
            }, {
                label: 'Falha',
                data: [
                    loginMetrics.last_hour?.failed || 0,
                    loginMetrics.last_24h?.failed || 0,
                    loginMetrics.last_week?.failed || 0
                ],
                borderColor: '#e74c3c',
                backgroundColor: 'rgba(231, 76, 60, 0.1)',
                tension: 0.1,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: value => formatNumber(value)
                    }
                }
            }
        }
    });
}

function updateTrendChart(alerts, metrics) {
    // Implementar gráfico de tendências
    // TODO: Adicionar implementação
}

function updateAlertsTable(alerts) {
    const tbody = document.querySelector('#recentAlerts tbody');
    tbody.innerHTML = '';

    const recentAlerts = alerts
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
        .slice(0, 5);

    recentAlerts.forEach(alert => {
        const row = document.createElement('tr');
        row.className = 'fade-in';
        row.innerHTML = `
            <td>${formatDateTime(alert.created_at)}</td>
            <td>${alert.type}</td>
            <td><span class="badge bg-${getSeverityClass(alert.severity)}">${alert.severity}</span></td>
            <td>${alert.message}</td>
            <td><span class="badge bg-${getStatusClass(alert.status)}">${alert.status}</span></td>
        `;
        tbody.appendChild(row);
    });
}

function updateAlertCount(alerts) {
    const newAlertCount = alerts.filter(alert =>
        alert.status === 'open' &&
        new Date(alert.created_at) > (state.lastUpdate || new Date(0))
    ).length;

    if (newAlertCount > 0) {
        state.alertCount += newAlertCount;
        document.getElementById('alertCount').textContent = state.alertCount;
        showNotification(`Novos alertas: ${newAlertCount}`);
    }
}

// Funções auxiliares
function formatNumber(num) {
    return new Intl.NumberFormat('pt-BR').format(num);
}

function formatDateTime(date) {
    return new Date(date).toLocaleString('pt-BR', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function getSeverityClass(severity) {
    switch (severity.toLowerCase()) {
        case 'high': return 'danger';
        case 'medium': return 'warning';
        case 'low': return 'info';
        default: return 'secondary';
    }
}

function getStatusClass(status) {
    switch (status.toLowerCase()) {
        case 'open': return 'danger';
        case 'in_progress': return 'warning';
        case 'resolved': return 'success';
        default: return 'secondary';
    }
}

// Funções de UI
function showLoading() {
    document.getElementById('loadingSpinner').classList.remove('d-none');
}

function hideLoading() {
    document.getElementById('loadingSpinner').classList.add('d-none');
}

function showError(message) {
    const toast = document.getElementById('toast');
    toast.querySelector('.toast-body').textContent = message;
    toast.classList.add('bg-danger', 'text-white');
    new bootstrap.Toast(toast).show();
}

function showNotification(message) {
    const toast = document.getElementById('toast');
    toast.querySelector('.toast-body').textContent = message;
    toast.classList.remove('bg-danger', 'text-white');
    new bootstrap.Toast(toast).show();
}

function setupTimeRangeSelector() {
    const timeRangeDropdown = document.getElementById('timeRangeDropdown');
    const selectedTimeRange = document.getElementById('selectedTimeRange');

    timeRangeDropdown.addEventListener('click', e => {
        e.preventDefault();
        const range = e.target.dataset.range;
        if (range) {
            updateTimeRange(range);
            selectedTimeRange.textContent = e.target.textContent;
        }
    });
}

function updateTimeRange(range) {
    state.currentTimeRange = range;
    updateDashboard();
}

function showCustomDateRangePicker() {
    // TODO: Implementar seletor de data personalizado
}

function setupSidebar() {
    const sidebarCollapse = document.getElementById('sidebarCollapse');
    const sidebar = document.getElementById('sidebar');
    const content = document.getElementById('content');

    sidebarCollapse.addEventListener('click', () => {
        sidebar.classList.toggle('active');
        content.classList.toggle('active');
    });
}

function setupNotifications() {
    if ('Notification' in window) {
        Notification.requestPermission();
    }
}

function showAlertsModal() {
    // TODO: Implementar modal de alertas
}

// Initialize Charts
let charts = {};

function initializeCharts() {
    // Alerts by Type Chart
    const alertsCtx = document.getElementById('alertsByTypeChart').getContext('2d');
    charts.alerts = new Chart(alertsCtx, {
        type: 'bar',
        data: {
            labels: ['Tentativa de Invasão', 'Acesso Suspeito', 'Transação Suspeita', 'Erro de Sistema', 'Outros'],
            datasets: [{
                label: 'Número de Alertas',
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    'rgba(78, 115, 223, 0.8)',
                    'rgba(28, 200, 138, 0.8)',
                    'rgba(246, 194, 62, 0.8)',
                    'rgba(231, 74, 59, 0.8)',
                    'rgba(133, 135, 150, 0.8)'
                ]
            }]
        },
        options: chartTypes.alerts.bar.options
    });

    // Login Attempts Chart
    const loginsCtx = document.getElementById('loginAttemptsChart').getContext('2d');
    charts.logins = new Chart(loginsCtx, {
        type: 'line',
        data: {
            labels: Array.from({ length: 24 }, (_, i) => `${i}:00`),
            datasets: [
                {
                    label: 'Sucesso',
                    data: Array(24).fill(0),
                    borderColor: 'rgba(28, 200, 138, 1)',
                    backgroundColor: 'rgba(28, 200, 138, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Falha',
                    data: Array(24).fill(0),
                    borderColor: 'rgba(231, 74, 59, 1)',
                    backgroundColor: 'rgba(231, 74, 59, 0.1)',
                    tension: 0.4
                }
            ]
        },
        options: chartTypes.logins.line.options
    });

    // Transactions Chart
    const transactionsCtx = document.getElementById('transactionsChart').getContext('2d');
    charts.transactions = new Chart(transactionsCtx, {
        type: 'line',
        data: {
            labels: Array.from({ length: 24 }, (_, i) => `${i}:00`),
            datasets: [{
                label: 'Volume de Transações',
                data: Array(24).fill(0),
                borderColor: 'rgba(54, 185, 204, 1)',
                backgroundColor: 'rgba(54, 185, 204, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            scales: {
                y: { beginAtZero: true }
            }
        }
    });

    // Risk Level Chart
    const riskCtx = document.getElementById('riskLevelChart').getContext('2d');
    charts.risk = new Chart(riskCtx, {
        type: 'radar',
        data: {
            labels: ['Tentativas de Invasão', 'Transações Suspeitas', 'Erros de Sistema', 'Falhas de Login', 'Vulnerabilidades'],
            datasets: [{
                label: 'Nível de Risco',
                data: [0, 0, 0, 0, 0],
                backgroundColor: 'rgba(78, 115, 223, 0.2)',
                borderColor: 'rgba(78, 115, 223, 1)',
                pointBackgroundColor: 'rgba(78, 115, 223, 1)',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: 'rgba(78, 115, 223, 1)'
            }]
        },
        options: {
            elements: {
                line: {
                    tension: 0.1
                }
            },
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
}

// Update Charts
function updateCharts() {
    fetch('/metrics')
        .then(response => response.json())
        .then(data => {
            // Update Alerts Chart
            charts.alerts.data.datasets[0].data = [
                data.metrics.invasion_attempts || 0,
                data.metrics.suspicious_access || 0,
                data.metrics.suspicious_transactions || 0,
                data.metrics.system_errors || 0,
                data.metrics.other_alerts || 0
            ];
            charts.alerts.update();

            // Update Logins Chart
            charts.logins.data.datasets[0].data = data.metrics.successful_logins || Array(24).fill(0);
            charts.logins.data.datasets[1].data = data.metrics.failed_logins || Array(24).fill(0);
            charts.logins.update();

            // Update Transactions Chart
            charts.transactions.data.datasets[0].data = data.metrics.transaction_volume || Array(24).fill(0);
            charts.transactions.update();

            // Update Risk Chart
            charts.risk.data.datasets[0].data = [
                data.metrics.invasion_risk || 0,
                data.metrics.transaction_risk || 0,
                data.metrics.system_risk || 0,
                data.metrics.login_risk || 0,
                data.metrics.vulnerability_risk || 0
            ];
            charts.risk.update();

            // Update Statistics Cards with Animation
            animateValue('alertsToday', data.metrics.alerts_today || 0);
            animateValue('successfulLogins', data.metrics.total_successful_logins || 0);
            animateValue('failedLogins', data.metrics.total_failed_logins || 0);
            animateValue('suspiciousTransactions', data.metrics.total_suspicious_transactions || 0);
        })
        .catch(error => {
            console.error('Error fetching metrics:', error);
            showToast('Erro ao atualizar métricas', 'error');
        });
}

// Animate Number Change
function animateValue(elementId, end, duration = 1000) {
    const obj = document.getElementById(elementId);
    const start = parseInt(obj.innerHTML);
    const range = end - start;
    const minTimer = 50;
    let stepTime = Math.abs(Math.floor(duration / range));
    stepTime = Math.max(stepTime, minTimer);

    let current = start;
    const step = Math.sign(range);

    function updateNumber() {
        current += step;
        obj.innerHTML = current;

        if (current != end) {
            setTimeout(updateNumber, stepTime);
        }
    }

    updateNumber();
}

// Chart Type Switcher
document.querySelectorAll('[data-chart]').forEach(button => {
    button.addEventListener('click', (e) => {
        e.preventDefault();
        const chartType = e.target.dataset.chart;
        const chartId = e.target.closest('.card').querySelector('canvas').id;
        const chartKey = chartId.replace('Chart', '');

        if (charts[chartKey] && chartTypes[chartKey] && chartTypes[chartKey][chartType]) {
            const config = chartTypes[chartKey][chartType];
            const oldData = charts[chartKey].data;

            charts[chartKey].destroy();
            charts[chartKey] = new Chart(document.getElementById(chartId).getContext('2d'), {
                type: config.type,
                data: oldData,
                options: config.options
            });
        }
    });
});

// Alert Details Modal
function showAlertDetails(alertId) {
    fetch(`/alerts/${alertId}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById('alertId').textContent = data.alert.id;
            document.getElementById('alertTimestamp').textContent = new Date(data.alert.timestamp).toLocaleString();
            document.getElementById('alertSeverity').textContent = data.alert.severity;
            document.getElementById('alertStatus').textContent = data.alert.status;
            document.getElementById('alertDetails').innerHTML = `<pre>${JSON.stringify(data.alert.details, null, 2)}</pre>`;

            const modal = new bootstrap.Modal(document.getElementById('alertDetailsModal'));
            modal.show();
        })
        .catch(error => {
            console.error('Error fetching alert details:', error);
            showToast('Erro ao carregar detalhes do alerta', 'error');
        });
}

// Toast Notifications
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    const toastBody = toast.querySelector('.toast-body');

    toast.classList.remove('bg-success', 'bg-danger', 'bg-info');
    toast.classList.add(`bg-${type === 'error' ? 'danger' : type}`);
    toastBody.textContent = message;

    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
}

// Exportar funções para testes
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        updateDashboard,
        updateStatistics,
        updateCharts,
        updateAlertsTable,
        formatNumber,
        formatDateTime,
        getSeverityClass,
        getStatusClass
    };
}