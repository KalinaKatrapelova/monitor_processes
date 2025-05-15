import psutil
import time
import os
import json
from flask import Flask, jsonify, request, render_template, Response
from flask_cors import CORS
import threading

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# Global variables
processes_data = []
monitoring_interval = 5  # Default monitoring interval in seconds
stop_monitoring = False
monitor_thread = None
filter_term = ""
sort_by = "cpu"
sort_order = "desc"
anomaly_threshold = 80  # Default threshold for anomaly detection

def get_process_info():
    """Get information about all running processes"""
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'ppid', 'status', 'num_threads', 'create_time']):
        try:
            # Get process info
            process_info = proc.info
            
            # Add child process information
            ppid = process_info.get('ppid', 0)
            is_child = ppid > 0
            
            if filter_term and filter_term.lower() not in process_info['name'].lower():
                continue
                
            process_data = {
                'pid': process_info['pid'],
                'name': process_info['name'],
                'cpu_percent': process_info['cpu_percent'],
                'memory_percent': round(process_info.get('memory_percent', 0), 2),
                'is_child': is_child,
                'parent_pid': ppid if is_child else None,
                'status': process_info.get('status', ''),
                'num_threads': process_info.get('num_threads', 0),
                'creation_time': process_info.get('create_time', 0)
            }
            processes.append(process_data)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    # Sort the processes
    reverse_order = sort_order == "desc"
    if sort_by == "pid":
        processes.sort(key=lambda x: x['pid'], reverse=reverse_order)
    elif sort_by == "name":
        processes.sort(key=lambda x: x['name'].lower(), reverse=reverse_order)
    elif sort_by == "cpu":
        processes.sort(key=lambda x: x['cpu_percent'], reverse=reverse_order)
    elif sort_by == "memory":
        processes.sort(key=lambda x: x['memory_percent'], reverse=reverse_order)
    elif sort_by == "parent_pid":
        processes.sort(key=lambda x: x['parent_pid'] if x['parent_pid'] is not None else -1, reverse=reverse_order)
    elif sort_by == "threads":
        processes.sort(key=lambda x: x['num_threads'], reverse=reverse_order)
    elif sort_by == "creation_time":
        processes.sort(key=lambda x: x['creation_time'], reverse=reverse_order)
    elif sort_by == "status":
        processes.sort(key=lambda x: x['status'], reverse=reverse_order)
    
    return processes

def detect_anomalies(current_processes, threshold=None):
    """Detect CPU or memory usage spikes above threshold"""
    if threshold is None:
        threshold = anomaly_threshold
        
    anomalies = []
    for proc in current_processes:
        if proc['cpu_percent'] > threshold:
            anomalies.append({
                'pid': proc['pid'],
                'name': proc['name'],
                'type': 'CPU usage',
                'value': proc['cpu_percent']
            })
        if proc['memory_percent'] > threshold:
            anomalies.append({
                'pid': proc['pid'],
                'name': proc['name'],
                'type': 'Memory usage',
                'value': proc['memory_percent']
            })
    return anomalies

def monitor_processes():
    """Monitor processes at the specified interval"""
    global processes_data, stop_monitoring
    
    while not stop_monitoring:
        # Refresh process info
        psutil.cpu_percent(interval=0.1)  # This helps get more accurate CPU readings
        
        # Collect all process data
        current_processes = get_process_info()
        processes_data = current_processes
        
        # Check for anomalies
        anomalies = detect_anomalies(current_processes)
        if anomalies:
            print("ANOMALY DETECTED:")
            for anomaly in anomalies:
                print(f"Process {anomaly['name']} (PID: {anomaly['pid']}) has high {anomaly['type']}: {anomaly['value']}%")
        
        # Wait for the specified interval
        time.sleep(monitoring_interval)

#
# Web UI routes (original) - kept for backward compatibility
#
@app.route('/')
def index():
    """Render the main monitoring page"""
    return render_template('index.html')

@app.route('/api/processes')
def get_processes():
    """API endpoint to get the latest process data"""
    return jsonify(processes_data)

@app.route('/api/settings', methods=['GET', 'POST'])  
def settings():
    """API  to get or upendpointdate monitoring settings"""
    global monitoring_interval, filter_term, sort_by, sort_order
    
    if request.method == 'POST':
        data = request.json
        if 'interval' in data:
            monitoring_interval = max(1, int(data['interval']))
        if 'filter' in data:
            filter_term = data['filter']
        if 'sort_by' in data:
            sort_by = data['sort_by']
        if 'sort_order' in data:
            sort_order = data['sort_order']
        return jsonify({'status': 'success'})
    
    return jsonify({
        'interval': monitoring_interval,
        'filter': filter_term,
        'sort_by': sort_by,
        'sort_order': sort_order
    })

# API version and info endpoint
@app.route('/api/v1/info', methods=['GET'])
def api_info():
    """Get API information and version"""
    return jsonify({
        'name': 'Process Monitor API',
        'version': '1.0',
        'description': 'REST API for monitoring system processes',
        'endpoints': {
            'processes': '/api/v1/processes',
            'system': '/api/v1/system',
            'settings': '/api/v1/settings',
            'anomalies': '/api/v1/anomalies',
            'process': '/api/v1/process/{pid}'
        }
    })

# Processes endpoint
@app.route('/api/v1/processes', methods=['GET'])
def api_processes():
    """Get all process data with optional filtering and sorting"""
    global processes_data
    
    # Get query parameters
    local_filter = request.args.get('filter', None)
    local_sort_by = request.args.get('sort_by', None)
    local_sort_order = request.args.get('sort_order', None)
    limit = request.args.get('limit', None)
    offset = request.args.get('offset', None)
    
    # Apply temporary filters for this request if specified
    filtered_data = processes_data
    
    # Apply filter if provided
    if local_filter:
        filtered_data = [p for p in filtered_data if local_filter.lower() in p['name'].lower()]
    
    # Apply sorting if provided
    if local_sort_by:
        reverse_sort = (local_sort_order or 'desc') == 'desc'
        
        # Define sort key function based on requested sort field
        if local_sort_by == "pid":
            key_func = lambda x: x['pid']
        elif local_sort_by == "name":
            key_func = lambda x: x['name'].lower()
        elif local_sort_by == "cpu":
            key_func = lambda x: x['cpu_percent']
        elif local_sort_by == "memory":
            key_func = lambda x: x['memory_percent']
        elif local_sort_by == "parent_pid":
            key_func = lambda x: x['parent_pid'] if x['parent_pid'] is not None else -1
        elif local_sort_by == "threads":
            key_func = lambda x: x['num_threads']
        elif local_sort_by == "creation_time":
            key_func = lambda x: x['creation_time']
        elif local_sort_by == "status":
            key_func = lambda x: x['status']
        else:
            key_func = lambda x: x['cpu_percent']  # Default
            
        filtered_data = sorted(filtered_data, key=key_func, reverse=reverse_sort)
    
   

# Individual process details endpoint
@app.route('/api/v1/process/<int:pid>', methods=['GET'])
def api_process_detail(pid):
    """Get detailed information about a specific process"""
    try:
        # Get process by PID
        process = psutil.Process(pid)
        
        # Get basic info
        basic_info = {
            'pid': process.pid,
            'name': process.name(),
            'status': process.status(),
            'create_time': process.create_time(),
            'cpu_percent': process.cpu_percent(interval=0.1),
            'memory_percent': process.memory_percent(),
            'memory_info': dict(process.memory_info()._asdict()),
            'num_threads': process.num_threads(),
            'username': process.username(),
            'parent_pid': process.ppid()
        }
        
        # Get additional details if 'extended' parameter is true
        if request.args.get('extended', '').lower() == 'true':
            try:
                # These may fail depending on permissions
                additional_info = {
                    'cmdline': process.cmdline(),
                    'cwd': process.cwd(),
                    'exe': process.exe(),
                    'open_files': [f._asdict() for f in process.open_files()],
                    'connections': [c._asdict() for c in process.connections()],
                    'threads': [t._asdict() for t in process.threads()],
                    'environ': process.environ() if hasattr(process, 'environ') else {},
                    'io_counters': process.io_counters()._asdict() if process.io_counters() else {},
                    'cpu_times': process.cpu_times()._asdict()
                }
                basic_info.update(additional_info)
            except (psutil.AccessDenied, psutil.ZombieProcess):
                basic_info['extended_error'] = 'Access denied for extended process information'
        
        return jsonify({
            'status': 'success',
            'data': basic_info
        })
    
    except psutil.NoSuchProcess:
        return jsonify({
            'status': 'error',
            'message': f'Process with PID {pid} not found'
        }), 404
    except psutil.AccessDenied:
        return jsonify({
            'status': 'error',
            'message': f'Access denied for process with PID {pid}'
        }), 403
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# System information endpoint
@app.route('/api/v1/system', methods=['GET'])
def api_system_info():
    """Get system-wide information"""
    # Get memory information
    memory = psutil.virtual_memory()._asdict()
    swap = psutil.swap_memory()._asdict()
    
    # Get CPU information
    cpu_count = {
        'physical': psutil.cpu_count(logical=False),
        'logical': psutil.cpu_count(logical=True)
    }
    cpu_percent = {
        'overall': psutil.cpu_percent(interval=0.1),
        'per_cpu': psutil.cpu_percent(interval=0.1, percpu=True)
    }
    
    # Get disk information
    disks = []
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            disk_info = {
                'device': partition.device,
                'mountpoint': partition.mountpoint,
                'fstype': partition.fstype,
                'opts': partition.opts,
                'total': usage.total,
                'used': usage.used,
                'free': usage.free, 
                'percent': usage.percent
            }
            disks.append(disk_info)
        except (PermissionError, FileNotFoundError):
            # Skip partitions that can't be accessed
            pass
    
    # Get network information
    net_io = psutil.net_io_counters()._asdict()
    net_connections = []
    
    try:
        for conn in psutil.net_connections():
            conn_info = {
                'fd': conn.fd,
                'family': conn.family,
                'type': conn.type,
                'laddr': conn.laddr._asdict() if conn.laddr else None,
                'raddr': conn.raddr._asdict() if conn.raddr else None,
                'status': conn.status,
                'pid': conn.pid
            }
            net_connections.append(conn_info)
    except psutil.AccessDenied:
        net_connections = []
    
    # Get boot time
    boot_time = psutil.boot_time()
    
    # Get process count
    process_count = len(list(psutil.process_iter()))
    
    return jsonify({
        'status': 'success',
        'data': {
            'cpu': {
                'count': cpu_count,
                'percent': cpu_percent
            },
            'memory': memory,
            'swap': swap,
            'disks': disks,
            'network': {
                'io_counters': net_io,
                'connections': net_connections if request.args.get('include_connections') == 'true' else []
            },
            'boot_time': boot_time,
            'process_count': process_count,
            'timestamp': time.time()
        }
    })

# Anomaly detection endpoint
@app.route('/api/v1/anomalies', methods=['GET'])
def api_anomalies():
    """Get processes that exceed resource thresholds"""
    global anomaly_threshold, processes_data
    
    # Get optional custom threshold from query parameters
    custom_threshold = request.args.get('threshold', None)
    threshold = int(custom_threshold) if custom_threshold else anomaly_threshold
    
    # Detect anomalies
    anomalies = detect_anomalies(processes_data, threshold)
    
    return jsonify({
        'status': 'success',
        'data': {
            'threshold': threshold,
            'anomalies': anomalies,
            'count': len(anomalies),
            'timestamp': time.time()
        }
    })

# Settings endpoint (API v1)
@app.route('/api/v1/settings', methods=['GET', 'PUT'])
def api_settings():
    """Get or update monitoring settings"""
    global monitoring_interval, filter_term, sort_by, sort_order, anomaly_threshold
    
    if request.method == 'PUT':
        data = request.json
        
        # Validate and update settings
        if 'interval' in data:
            if isinstance(data['interval'], (int, float)) and data['interval'] >= 1:
                monitoring_interval = data['interval']
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Interval must be a number >= 1'
                }), 400
                
        if 'filter' in data:
            filter_term = str(data['filter'])
            
        if 'sort_by' in data:
            valid_sort_options = ['pid', 'name', 'cpu', 'memory', 
                                  'parent_pid', 'threads', 'creation_time', 'status']
            if data['sort_by'] in valid_sort_options:
                sort_by = data['sort_by']
            else:
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid sort_by option. Must be one of: {", ".join(valid_sort_options)}'
                }), 400
                
        if 'sort_order' in data:
            if data['sort_order'] in ['asc', 'desc']:
                sort_order = data['sort_order']
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Sort order must be "asc" or "desc"'
                }), 400
                
        if 'anomaly_threshold' in data:
            if isinstance(data['anomaly_threshold'], (int, float)) and 0 <= data['anomaly_threshold'] <= 100:
                anomaly_threshold = data['anomaly_threshold']
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Anomaly threshold must be a number between 0 and 100'
                }), 400
        
        return jsonify({
            'status': 'success',
            'data': {
                'interval': monitoring_interval,
                'filter': filter_term,
                'sort_by': sort_by,
                'sort_order': sort_order,
                'anomaly_threshold': anomaly_threshold
            }
        })
    
    else:  # GET
        return jsonify({
            'status': 'success',
            'data': {
                'interval': monitoring_interval,
                'filter': filter_term,
                'sort_by': sort_by,
                'sort_order': sort_order,
                'anomaly_threshold': anomaly_threshold
            }
        })

# Process monitoring control endpoint
@app.route('/api/v1/control', methods=['POST'])
def api_control():
    """Control the monitoring process"""
    global monitor_thread, stop_monitoring
    
    action = request.json.get('action')
    
    if action == 'start':
        if monitor_thread and monitor_thread.is_alive():
            return jsonify({
                'status': 'warning',
                'message': 'Monitoring is already running'
            })
        
        # Start the monitoring thread
        stop_monitoring = False
        monitor_thread = threading.Thread(target=monitor_processes)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return jsonify({
            'status': 'success',
            'message': 'Monitoring started'
        })
        
    elif action == 'stop':
        if not monitor_thread or not monitor_thread.is_alive():
            return jsonify({
                'status': 'warning',
                'message': 'Monitoring is not running'
            })
        
        # Stop the monitoring thread
        stop_monitoring = True
        monitor_thread.join(timeout=2)
        
        return jsonify({
            'status': 'success',
            'message': 'Monitoring stopped'
        })
        
    elif action == 'restart':
        # Stop existing thread if running
        if monitor_thread and monitor_thread.is_alive():
            stop_monitoring = True
            monitor_thread.join(timeout=2)
        
        # Start new thread
        stop_monitoring = False
        monitor_thread = threading.Thread(target=monitor_processes)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return jsonify({
            'status': 'success',
            'message': 'Monitoring restarted'
        })
        
    elif action == 'status':
        is_running = monitor_thread and monitor_thread.is_alive()
        
        return jsonify({
            'status': 'success',
            'data': {
                'running': is_running,
                'interval': monitoring_interval
            }
        })
        
    else:
        return jsonify({
            'status': 'error',
            'message': f'Unknown action: {action}. Valid actions are: start, stop, restart, status'
        }), 400

# Process termination endpoint
@app.route('/api/v1/process/<int:pid>/terminate', methods=['POST'])
def api_terminate_process(pid):
    """Terminate a specific process by PID"""
    try:
        # Get process by PID
        process = psutil.Process(pid)
        
        # Get process info before termination
        process_info = {
            'pid': process.pid,
            'name': process.name(),
            'status': process.status()
        }
        
        # Check for confirmation
        if not request.json or request.json.get('confirm') != True:
            return jsonify({
                'status': 'warning',
                'message': 'Termination requires confirmation',
                'process': process_info
            }), 400
        
        # Attempt to terminate the process
        process.terminate()
        
        # Give it some time to terminate
        gone, alive = psutil.wait_procs([process], timeout=3)
        
        if process in alive:
            # Process didn't terminate, try to kill it
            process.kill()
            gone, alive = psutil.wait_procs([process], timeout=3)
            
            if process in alive:
                return jsonify({
                    'status': 'error',
                    'message': f'Failed to terminate process {pid}',
                    'process': process_info
                }), 500
            else:
                return jsonify({
                    'status': 'success',
                    'message': f'Process {pid} killed forcefully',
                    'process': process_info
                })
        else:
            return jsonify({
                'status': 'success',
                'message': f'Process {pid} terminated successfully',
                'process': process_info
            })
            
    except psutil.NoSuchProcess:
        return jsonify({
            'status': 'error',
            'message': f'Process with PID {pid} not found'
        }), 404
    except psutil.AccessDenied:
        return jsonify({
            'status': 'error',
            'message': f'Access denied when attempting to terminate process with PID {pid}'
        }), 403
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def start_monitoring():
    """Start the monitoring thread"""
    global stop_monitoring, monitor_thread
    stop_monitoring = False
    monitor_thread = threading.Thread(target=monitor_processes)
    monitor_thread.daemon = True
    monitor_thread.start()

def shutdown_monitoring():
    """Stop the monitoring thread"""
    global stop_monitoring
    stop_monitoring = True
    if monitor_thread:
        monitor_thread.join(timeout=2)

if __name__ == '__main__':
    # Create the templates and static directories if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    try:
        # Start the monitoring thread
        start_monitoring()
        
        # Start the Flask app
        app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)
    finally:
        # Ensure the monitoring thread is stopped when the app exits
        shutdown_monitoring()