// Global settings
let settings = {
  interval: 5,
  filter: '',
  sort_by: 'cpu',
  sort_order: 'desc'
};

// DOM elements
const processesBody = document.getElementById('processes-body');
const intervalInput = document.getElementById('interval');
const filterInput = document.getElementById('filter');
const applySettingsBtn = document.getElementById('apply-settings');
const anomalyAlert = document.getElementById('anomaly-alert');
const tableHeaders = document.querySelectorAll('th[data-sort]');

// Initialize the UI
function initUI() {
  // Set up event listeners
  applySettingsBtn.addEventListener('click', applySettings);
  
  // Set up sorting headers
  tableHeaders.forEach(header => {
    header.addEventListener('click', () => {
      const sortBy = header.getAttribute('data-sort');
      if (settings.sort_by === sortBy) {
        // Toggle sort order if already sorting by this column
        settings.sort_order = settings.sort_order === 'asc' ? 'desc' : 'asc';
      } else {
        // Set new sort column and default to descending
        settings.sort_by = sortBy;
        settings.sort_order = 'desc';
      }
      
      // Update UI immediately without waiting for server
      updateSortIndicators();
      
      // Fetch the current data and sort locally
      fetch('/api/processes')
        .then(response => response.json())
        .then(data => {
          // Sort locally for immediate feedback
          sortProcessesClientSide(data);
          renderProcesses(data);
          
          // Also update server settings in background
          fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
          });
        });
    });
    
    // Add tooltip for sortable columns
    const tooltip = document.createElement('span');
    tooltip.className = 'tooltiptext';
    tooltip.textContent = 'Click to sort';
    header.classList.add('tooltip');
    header.appendChild(tooltip);
  });

  // Set initial sort indicators
  updateSortIndicators();

  // Fetch initial settings from the server
  fetchSettings();

  // Immediately fetch processes for the first time
  fetchProcesses();

  // Set up interval for data refresh
  setInterval(fetchProcesses, settings.interval * 1000);
}

// Fetch settings from the server
function fetchSettings() {
  fetch('/api/settings')
    .then(response => {
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    })
    .then(data => {
      // Update local settings
      settings = data;
      
      // Update UI
      intervalInput.value = settings.interval;
      filterInput.value = settings.filter;
      updateSortIndicators();
      
      // Force refresh of data after settings are loaded
      fetchProcesses();
      
      console.log('Initial settings loaded:', settings);
    })
    .catch(error => {
      console.error('Error fetching settings:', error);
      // Still try to fetch processes even if settings fail
      fetchProcesses();
    });
}

// Update sort indicators in the table headers
function updateSortIndicators() {
  tableHeaders.forEach(header => {
    const indicator = header.querySelector('.sort-indicator');
    const sortBy = header.getAttribute('data-sort');
    
    // Reset all headers
    header.classList.remove('active-sort');
    
    if (sortBy === settings.sort_by) {
      // Mark this header as active
      header.classList.add('active-sort');
      indicator.textContent = settings.sort_order === 'asc' ? '▲' : '▼';
      indicator.style.fontWeight = 'bold';
    } else {
      // Set empty indicator for non-active columns
      indicator.textContent = '';
    }
  });
}

// Apply user settings
function applySettings() {
  // Get values from inputs
  const newInterval = parseInt(intervalInput.value);
  const newFilter = filterInput.value.trim();
  
  // Validate and update settings
  if (newInterval >= 1) {
    settings.interval = newInterval;
  } else {
    intervalInput.value = settings.interval;
  }

  settings.filter = newFilter;

  // Update sort indicators
  updateSortIndicators();
  
  // Send settings to server
  fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings)
  })
  .then(response => {
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    return response.json();
  })
  .then(() => {
    // Force refresh of data
    fetchProcesses();
  })
  .catch(error => console.error('Error updating settings:', error));
}

// Fetch process data from the API
function fetchProcesses() {
  fetch('/api/processes')
    .then(response => {
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    })
    .then(data => {
      // Sort data client-side for better performance
      sortProcessesClientSide(data);
      renderProcesses(data);
      checkForAnomalies(data);
    })
    .catch(error => {
      console.error('Error fetching processes:', error);
      processesBody.innerHTML = `<tr><td colspan="8">Error loading process data. ${error.message}</td></tr>`;
    });
}

// Sort processes client-side for better performance
function sortProcessesClientSide(processes) {
  const reverse = settings.sort_order === "desc";
  
  processes.sort((a, b) => {
    let valueA, valueB;
    
    switch(settings.sort_by) {
      case "pid":
        valueA = a.pid;
        valueB = b.pid;
        break;
      case "name":
        valueA = a.name.toLowerCase();
        valueB = b.name.toLowerCase();
        break;
      case "cpu":
        valueA = a.cpu_percent;
        valueB = b.cpu_percent;
        break;
      case "memory":
        valueA = a.memory_percent;
        valueB = b.memory_percent;
        break;
      case "parent_pid":
        valueA = a.parent_pid || -1;
        valueB = b.parent_pid || -1;
        break;
      case "threads":
        valueA = a.num_threads || 0;
        valueB = b.num_threads || 0;
        break;
      case "creation_time":
        valueA = a.creation_time || 0;
        valueB = b.creation_time || 0;
        break;
      case "status":
        valueA = a.status || "";
        valueB = b.status || "";
        break;
      default:
        valueA = a.cpu_percent;
        valueB = b.cpu_percent;
    }
    
    if (valueA < valueB) return reverse ? 1 : -1;
    if (valueA > valueB) return reverse ? -1 : 1;
    return 0;
  });
}

// Render the processes table
function renderProcesses(processes) {
  if (!processes || processes.length === 0) {
    processesBody.innerHTML = '<tr><td colspan="8">No processes found</td></tr>';
    return;
  }

  // Clear the table
  processesBody.innerHTML = '';

  // Add rows for each process
  processes.forEach(process => {
    try {
      const row = document.createElement('tr');
      
      // Add anomaly class if CPU or memory usage is high
      if (process.cpu_percent > 80 || process.memory_percent > 80) {
        row.classList.add('anomaly');
      }
      
      // Format creation time
      let creationTime = '-';
      if (process.creation_time) {
        try {
          creationTime = new Date(process.creation_time * 1000).toLocaleString();
        } catch (e) {
          console.error('Error formatting time:', e);
          creationTime = '-';
        }
      }
      
      // Format the process name - add arrow prefix for child processes
      let processName = process.name;
      if (process.is_child) {
        processName = '↳ ' + processName;
      }
      
      // Format the row content
      row.innerHTML = `
        <td>${process.pid}</td>
        <td>${processName}</td>
        <td>${process.cpu_percent.toFixed(1)}</td>
        <td>${process.memory_percent.toFixed(1)}</td>
        <td>${process.parent_pid || '-'}</td>
        <td>${process.num_threads || '-'}</td>
        <td>${creationTime}</td>
        <td>${process.status || '-'}</td>
      `;
      
      processesBody.appendChild(row);
    } catch (err) {
      console.error('Error rendering process row:', err, process);
    }
  });
}

// Check for anomalies in process data
function checkForAnomalies(processes) {
  const anomalies = processes.filter(p => p.cpu_percent > 80 || p.memory_percent > 80);
  if (anomalies.length > 0) {
    // Show the anomaly alert
    anomalyAlert.style.display = 'block';
    
    // Create alert message with details
    let message = '<strong>Alert!</strong> High resource usage detected:<br>';
    anomalies.forEach(a => {
      message += `Process '${a.name}' (PID: ${a.pid}): `;
      if (a.cpu_percent > 80) message += `CPU ${a.cpu_percent.toFixed(1)}% `;
      if (a.memory_percent > 80) message += `MEM ${a.memory_percent.toFixed(1)}%`;
      message += '<br>';
    });
    
    anomalyAlert.innerHTML = message;
  } else {
    // Hide the alert if no anomalies
    anomalyAlert.style.display = 'none';
  }
}

// Initialize when the page loads
document.addEventListener('DOMContentLoaded', initUI);