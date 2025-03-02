const socket = io();
const ctx = document.getElementById('eventChart').getContext('2d');

const chart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'High Severity',
            data: [],
            borderColor: '#dc3545',
            backgroundColor: '#dc354520',
            fill: true
        }, {
            label: 'Medium Severity',
            data: [],
            borderColor: '#ffc107',
            backgroundColor: '#ffc10720',
            fill: true
        }, {
            label: 'Low Severity',
            data: [],
            borderColor: '#28a745',
            backgroundColor: '#28a74520',
            fill: true
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true,
                stacked: true
            }
        }
    }
});

// Remove duplicate event listeners and consolidate socket handling
socket.on('connect', () => {
    console.log('Connected to server');
    socket.emit('client_ready');
});

socket.on('disconnect', () => {
    console.log('Disconnected from server');
});

socket.on('new_event', function(event) {
    console.log('Received event:', event);
    updateChart(event);
    addEventToTable(event);
    updateStats();
});

// Remove duplicate updateFileList function and keep only one version
function updateFileList() {
    fetch('/api/files')
        .then(response => response.json())
        .then(data => {
            console.log('Files updated:', data);
            updateSelect('pcap-select', data.pcap_files || []);
            updateSelect('report-select', data.report_files || []);
        })
        .catch(error => console.error('File list update error:', error));
}

// Initialize with shorter intervals
updateFileList();
updateStats();
setInterval(updateFileList, 5000);  // Check files every 5 seconds
setInterval(updateStats, 5000);     // Update stats every 5 seconds
// Update chart update function
function updateChart(event) {
    if (!event) return;
    
    const now = new Date().toLocaleTimeString();
    chart.data.labels.push(now);

    const dataPoint = {
        high: event.severity === 'High' ? 1 : 0,
        medium: event.severity === 'Medium' ? 1 : 0,
        low: event.severity === 'Low' ? 1 : 0
    };

    chart.data.datasets[0].data.push(dataPoint.high);
    chart.data.datasets[1].data.push(dataPoint.medium);
    chart.data.datasets[2].data.push(dataPoint.low);

    if (chart.data.labels.length > 30) {
        chart.data.labels.shift();
        chart.data.datasets.forEach(dataset => dataset.data.shift());
    }

    chart.update('none');
}
function addEventToTable(event) {
    const table = document.getElementById('events-table');
    const row = table.insertRow(0);
    
    row.className = event.severity === 'High' ? 'table-danger' : 
                    event.severity === 'Medium' ? 'table-warning' : 'table-success';
    
    row.insertCell(0).textContent = event.timestamp;
    row.insertCell(1).textContent = event.source_ip;
    row.insertCell(2).textContent = event.target_ip;
    row.insertCell(3).textContent = event.protocol;
    row.insertCell(4).textContent = event.severity;

    if (table.rows.length > 100) {
        table.deleteRow(-1);
    }
}
// Add these functions after the existing code
function updateFileList() {
    fetch('/api/files')
        .then(response => response.json())
        .then(data => {
            updateSelect('pcap-select', data.pcap_files || []);
            updateSelect('report-select', data.report_files || []);
        });
}

function updateSelect(id, files) {
    const select = document.getElementById(id);
    const defaultOption = select.options[0];
    select.innerHTML = '';
    select.appendChild(defaultOption);
    files.forEach(file => {
        const option = document.createElement('option');
        option.value = file;
        option.textContent = file;
        select.appendChild(option);
    });
}

function downloadSelected(type) {
    const select = document.getElementById(`${type}-select`);
    const filename = select.value;
    
    if (!filename) {
        alert(`Please select a ${type.toUpperCase()} file`);
        return;
    }

    window.location.href = `/api/download/${filename}`;
}

// Add to initialization
updateFileList();
setInterval(updateFileList, 30000);
function updateStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('total-events').textContent = data.total_events;
            document.getElementById('high-severity').textContent = data.high_severity;
            document.getElementById('unique-sources').textContent = data.unique_sources;
        });
}

document.getElementById('toggleScan').addEventListener('click', function() {
    const button = this;
    button.disabled = true;

    fetch('/api/control/toggle', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'}
    })
    .then(response => response.json())
    .then(data => {
        button.textContent = data.scanning ? 'Stop Scanning' : 'Start Scanning';
        button.className = `btn ${data.scanning ? 'btn-danger' : 'btn-success'}`;
    })
    .finally(() => {
        setTimeout(() => button.disabled = false, 1000);
    });
});

updateStats();
setInterval(updateStats, 30000);