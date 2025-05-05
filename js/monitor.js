// Initialize Socket.IO connection
const socket = io();

// Initialize Chart
const ctx = document.getElementById('eventChart').getContext('2d');

// Initialize Chart
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

// Event Handlers
socket.on('new_event', function(event) {
    updateChart(event);
    addEventToTable(event);
    updateStats();
});

// Throttle chart updates
let updateTimeout = null;
function updateChart(event) {
    if (updateTimeout) return;
    
    updateTimeout = setTimeout(() => {
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
    
        if (chart.data.labels.length > 20) { // Reduced points for better visibility
            chart.data.labels.shift();
            chart.data.datasets.forEach(dataset => dataset.data.shift());
        }
    
        chart.update('none'); // Use 'none' mode for smoother updates
        updateTimeout = null;
    }, 2000); // Update every 2 seconds
}
// Update the download function
function downloadSelected(type) {
    const select = document.getElementById(`${type}-select`);
    const filename = select.value;
    
    if (!filename) {
        alert(`Please select a ${type.toUpperCase()} file`);
        return;
    }

    window.location.href = `/api/download/${filename}`;
}

// Improve button handling
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
        updateFileList(); // Refresh file lists after toggle
    })
    .finally(() => {
        setTimeout(() => {
            button.disabled = false;
        }, 1000);
    });
});

// Update file list refresh
function updateFileList() {
    fetch('/api/files')
        .then(response => response.json())
        .then(data => {
            const pcapSelect = document.getElementById('pcap-select');
            const reportSelect = document.getElementById('report-select');
            
            // Update PCAP files
            pcapSelect.innerHTML = '<option value="">Select PCAP file...</option>';
            data.pcap_files.forEach(file => {
                pcapSelect.add(new Option(file, file));
            });
            
            // Update Report files
            reportSelect.innerHTML = '<option value="">Select Report file...</option>';
            data.report_files.forEach(file => {
                reportSelect.add(new Option(file, file));
            });
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

// Initialize with file list updates
updateFileList();
setInterval(updateFileList, 30000);
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
}

function updateStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('total-events').textContent = data.total_events;
            document.getElementById('high-severity').textContent = data.high_severity;
            document.getElementById('unique-sources').textContent = data.unique_sources;
        });
}

// Toggle Scanning
// Add the application shutdown function
function stopApplication() {
    const button = document.getElementById('toggleScan');
    button.disabled = true;

    fetch('/api/control/shutdown', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'}
    })
    .then(response => response.json())
    .then(data => {
        console.log('Server shutting down:', data);
        button.textContent = 'Server Stopped';
        button.className = 'btn btn-secondary';
        
        // Show shutdown message to user
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-warning';
        alertDiv.textContent = 'Application is shutting down. You can close this window.';
        document.body.insertBefore(alertDiv, document.body.firstChild);
        
        // Disable all interactive elements
        disableInterface();
    })
    .catch(error => {
        console.error('Error shutting down server:', error);
        button.disabled = false;
    });
}

function disableInterface() {
    // Disable all buttons and selects
    document.querySelectorAll('button, select').forEach(element => {
        element.disabled = true;
    });
    
    // Stop updating stats and file list
    clearInterval(statsInterval);
    clearInterval(fileListInterval);
    
    // Disconnect socket
    socket.disconnect();
}

// Modify the existing toggle button event listener
document.getElementById('toggleScan').addEventListener('click', function() {
    const button = this;
    
    // Disable button immediately
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
    .catch(error => {
        console.error('Toggle error:', error);
        // Revert button state on error
        button.className = 'btn btn-warning';
        button.textContent = 'Error';
    })
    .finally(() => {
        // Enable button faster
        setTimeout(() => {
            button.disabled = false;
        }, 500); // Reduced from 1000 to 500ms
    });
});

// Add socket listener for immediate status updates
socket.on('scanning_status', function(data) {
    const button = document.getElementById('toggleScan');
    button.textContent = data.scanning ? 'Stop Scanning' : 'Start Scanning';
    button.className = `btn ${data.scanning ? 'btn-danger' : 'btn-success'}`;
});

// Update file list refresh
function updateFileList() {
    fetch('/api/files')
        .then(response => response.json())
        .then(data => {
            const pcapSelect = document.getElementById('pcap-select');
            const reportSelect = document.getElementById('report-select');
            
            // Update PCAP files
            pcapSelect.innerHTML = '<option value="">Select PCAP file...</option>';
            data.pcap_files.forEach(file => {
                pcapSelect.add(new Option(file, file));
            });
            
            // Update Report files
            reportSelect.innerHTML = '<option value="">Select Report file...</option>';
            data.report_files.forEach(file => {
                reportSelect.add(new Option(file, file));
            });
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

// Initialize with file list updates
updateFileList();
setInterval(updateFileList, 30000);
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
}

function updateStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('total-events').textContent = data.total_events;
            document.getElementById('high-severity').textContent = data.high_severity;
            document.getElementById('unique-sources').textContent = data.unique_sources;
        });
}

// Toggle Scanning
// Add the application shutdown function
function stopApplication() {
    const button = document.getElementById('toggleScan');
    button.disabled = true;

    fetch('/api/control/shutdown', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'}
    })
    .then(response => response.json())
    .then(data => {
        console.log('Server shutting down:', data);
        button.textContent = 'Server Stopped';
        button.className = 'btn btn-secondary';
        
        // Show shutdown message to user
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-warning';
        alertDiv.textContent = 'Application is shutting down. You can close this window.';
        document.body.insertBefore(alertDiv, document.body.firstChild);
        
        // Disable all interactive elements
        disableInterface();
    })
    .catch(error => {
        console.error('Error shutting down server:', error);
        button.disabled = false;
    });
}

function disableInterface() {
    // Disable all buttons and selects
    document.querySelectorAll('button, select').forEach(element => {
        element.disabled = true;
    });
    
    // Stop updating stats and file list
    clearInterval(statsInterval);
    clearInterval(fileListInterval);
    
    // Disconnect socket
    socket.disconnect();
}

// Modify the existing toggle button event listener
document.getElementById('toggleScan').addEventListener('click', function() {
    const button = this;
    button.disabled = true;

    if (button.textContent === 'Stop Scanning') {
        // If stopping, shutdown the application
        stopApplication();
    } else {
        // Normal toggle functionality
        fetch('/api/control/toggle', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        })
        .then(response => response.json())
        .then(data => {
            button.textContent = data.scanning ? 'Stop Scanning' : 'Start Scanning';
            button.className = `btn ${data.scanning ? 'btn-danger' : 'btn-success'}`;
            updateFileList();
        })
        .finally(() => {
            setTimeout(() => {
                button.disabled = false;
            }, 1000);
        });
    }
});

// Store interval references for cleanup
const statsInterval = setInterval(updateStats, 30000);
const fileListInterval = setInterval(updateFileList, 30000);
