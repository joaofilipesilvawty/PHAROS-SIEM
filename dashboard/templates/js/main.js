// Dashboard functionality
document.addEventListener('DOMContentLoaded', function() {
    // Handle logout
    const logoutButton = document.getElementById('logout-button');
    if (logoutButton) {
        logoutButton.addEventListener('click', function(e) {
            e.preventDefault();
            fetch('/auth/logout', {
                method: 'GET',
                credentials: 'same-origin'
            }).then(() => {
                window.location.href = '/login';
            });
        });
    }

    // Handle alerts dismissal
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        const closeButton = alert.querySelector('.close');
        if (closeButton) {
            closeButton.addEventListener('click', function() {
                alert.style.display = 'none';
            });
        }
    });

    // Auto-update metrics
    function updateMetrics() {
        fetch('/metrics', {
            credentials: 'same-origin'
        })
        .then(response => response.json())
        .then(data => {
            Object.keys(data.metrics).forEach(key => {
                const element = document.getElementById(`metric-${key}`);
                if (element) {
                    element.textContent = data.metrics[key];
                }
            });
        })
        .catch(console.error);
    }

    // Update metrics every 30 seconds
    setInterval(updateMetrics, 30000);

    // Initialize charts if they exist
    if (typeof Chart !== 'undefined' && document.getElementById('activityChart')) {
        const ctx = document.getElementById('activityChart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: window.activityTimeline.labels,
                datasets: [{
                    label: 'Activity',
                    data: window.activityTimeline.data,
                    borderColor: '#4e73df',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    }
});