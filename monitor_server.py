import json
import os
import platform
import shutil
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).parent
previous_network = None
previous_network_time = None
previous_cpu = None
file_scan_lock = threading.Lock()
file_scan_state = {
    'status': 'starting',
    'checked': 0,
    'changed': 0,
    'last_scan_ns': 0,
    'duration_ns': 0,
    'interval_ms': 1000,
}


def file_snapshot():
    snapshot = {}
    ignored_directories = {'.git', '__pycache__', 'build', 'cmake-build'}
    for directory, subdirectories, filenames in os.walk(ROOT):
        subdirectories[:] = [item for item in subdirectories if item not in ignored_directories]
        for filename in filenames:
            path = Path(directory) / filename
            try:
                details = path.stat()
            except OSError:
                continue
            snapshot[str(path.relative_to(ROOT))] = (
                details.st_size,
                details.st_mtime_ns,
                details.st_mode,
            )
    return snapshot


def file_monitor(interval_ms):
    previous_snapshot = file_snapshot()
    while True:
        started = time.perf_counter_ns()
        current_snapshot = file_snapshot()
        changed = sum(
            previous_snapshot.get(path) != details
            for path, details in current_snapshot.items()
        )
        changed += len(set(previous_snapshot) - set(current_snapshot))
        finished = time.perf_counter_ns()
        with file_scan_lock:
            file_scan_state.update({
                'status': 'healthy',
                'checked': len(current_snapshot),
                'changed': changed,
                'last_scan_ns': finished,
                'duration_ns': finished - started,
                'interval_ms': interval_ms,
            })
        previous_snapshot = current_snapshot
        time.sleep(interval_ms / 1000)


def file_scan_metrics():
    with file_scan_lock:
        return dict(file_scan_state)


def choose_network_interface():
    interfaces = []
    for name in os.listdir('/sys/class/net'):
        if name == 'lo':
            continue
        interface_path = Path('/sys/class/net') / name
        is_physical = (interface_path / 'device').exists()
        interfaces.append((not is_physical, name))
    return sorted(interfaces)[0][1] if interfaces else None


def network_bytes(interface):
    if not interface:
        return 0
    with open('/proc/net/dev', encoding='utf-8') as network_file:
        for line in network_file:
            if f'{interface}:' not in line:
                continue
            values = line.split(':', 1)[1].split()
            return int(values[0]) + int(values[8])
    return 0


def cpu_usage():
    global previous_cpu
    with open('/proc/stat', encoding='utf-8') as stat_file:
        values = stat_file.readline().split()[1:]
    current = tuple(map(int, values))
    idle = current[3] + current[4]
    total = sum(current)
    usage = 0.0
    if previous_cpu:
        previous_total, previous_idle = previous_cpu
        total_delta = total - previous_total
        idle_delta = idle - previous_idle
        if total_delta:
            usage = (1 - idle_delta / total_delta) * 100
    previous_cpu = (total, idle)
    return round(max(0, min(100, usage)))


def ram_usage():
    memory = {}
    with open('/proc/meminfo', encoding='utf-8') as memory_file:
        for line in memory_file:
            key, value = line.split(':', 1)
            memory[key] = int(value.split()[0])
    total = memory.get('MemTotal', 1)
    available = memory.get('MemAvailable', memory.get('MemFree', 0))
    return round((1 - available / total) * 100)


def metrics():
    global previous_network, previous_network_time
    interface = choose_network_interface()
    current_bytes = network_bytes(interface)
    current_time = time.monotonic()
    speed_mbps = 0
    if previous_network is not None and previous_network_time is not None:
        elapsed = current_time - previous_network_time
        if elapsed > 0:
            speed_mbps = round((max(0, current_bytes - previous_network) * 8) / elapsed / 1_000_000)
    previous_network = current_bytes
    previous_network_time = current_time
    disk = shutil.disk_usage('/')
    return {
        'interface': interface or 'unavailable',
        'architecture': f'{platform.architecture()[0]} / {platform.machine()}',
        'os': f'{platform.system()} {platform.release()}',
        'ram': ram_usage(),
        'disk': round((disk.used / disk.total) * 100),
        'cpu': cpu_usage(),
        'internet': speed_mbps,
        'files': file_scan_metrics(),
    }


class MonitorHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        started = time.perf_counter_ns()
        if self.path == '/api/metrics':
            payload = metrics()
            payload['latency'] = time.perf_counter_ns() - started
            response = json.dumps(payload).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            return
        super().do_GET()


if __name__ == '__main__':
    os.chdir(ROOT)
    host = os.environ.get('MONITOR_HOST', '127.0.0.1')
    port = int(os.environ.get('MONITOR_PORT', '8000'))
    interval_ms = max(10, int(os.environ.get('FILE_SCAN_INTERVAL_MS', '1000')))
    threading.Thread(target=file_monitor, args=(interval_ms,), daemon=True).start()
    server = ThreadingHTTPServer((host, port), MonitorHandler)
    print(f'Monitoring server: http://{host}:{port}')
    server.serve_forever()