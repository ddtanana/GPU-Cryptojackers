import subprocess
import time
import psutil
import numpy as np
from collections import defaultdict

# Configuration
SAMPLE_INTERVAL = 1  # seconds between samples
MIN_SAMPLES = 10  # minimum samples to compute stats
MAX_SAMPLES = 30  # keep last N samples to compute rolling stats
GPU_UTIL_THRESHOLD = 90.0  # %
GPU_MEM_THRESHOLD = 90.0  # %
RAM_THRESHOLD = 4.5 * 1024 * 1024 * 1024  # 4.5 GB in bytes
STD_DEV_THRESHOLD = 3.5  # assuming this is the "average quadratic deviation" interpreted as std dev

# Store historical data per PID: lists of gpu_util, gpu_mem_perc, ram_usage
process_history = defaultdict(lambda: {'gpu_util': [], 'gpu_mem_perc': [], 'ram': [], 'name': None})

def get_total_gpu_memory():
    try:
        output = subprocess.check_output(['nvidia-smi', '--query-gpu=memory.total', '--format=csv,noheader,nounits'])
        return int(output.decode().strip()) * 1024 * 1024  # MB to bytes
    except Exception as e:
        print(f"Error getting total GPU memory: {e}")
        return None

def collect_metrics(total_mem):
    current_processes = {}
    
    # Get compute apps for PIDs, names, used GPU memory
    try:
        output = subprocess.check_output(['nvidia-smi', '--query-compute-apps=pid,process_name,used_memory', '--format=csv,noheader,nounits'])
        lines = output.decode().strip().split('\n')
        for line in lines:
            if line.strip():
                pid_str, name, used_mem_mb = line.split(', ')
                pid = int(pid_str)
                used_mem = int(used_mem_mb) * 1024 * 1024  # MB to bytes
                mem_perc = (used_mem / total_mem * 100) if total_mem else 0
                current_processes[pid] = {'name': name, 'gpu_mem_perc': mem_perc, 'gpu_util': 0}
    except Exception as e:
        print(f"Error querying compute apps: {e}")
        return
    
    # Get process utilization (SM % as GPU util)
    try:
        output = subprocess.check_output(['nvidia-smi', 'pmon', '-c', '1', '-s', 'u'])
        lines = output.decode().split('\n')
        for line in lines:
            if not line.startswith('#') and line.strip():
                parts = line.split()
                if len(parts) >= 5 and parts[1] != '-':
                    pid = int(parts[1])
                    sm_util = parts[3] if parts[3] != '-' else '0'
                    if pid in current_processes:
                        current_processes[pid]['gpu_util'] = int(sm_util)
    except Exception as e:
        print(f"Error running pmon: {e}")
        return
    
    # Update history
    seen_pids = set()
    for pid, data in current_processes.items():
        seen_pids.add(pid)
        if process_history[pid]['name'] is None:
            process_history[pid]['name'] = data['name']
        process_history[pid]['gpu_util'].append(data['gpu_util'])
        process_history[pid]['gpu_mem_perc'].append(data['gpu_mem_perc'])
        
        # Get RAM usage
        try:
            proc = psutil.Process(pid)
            ram = proc.memory_info().rss
            process_history[pid]['ram'].append(ram)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_history[pid]['ram'].append(0)
    
    # Clean up history for unseen processes
    for pid in list(process_history.keys()):
        if pid not in seen_pids:
            # If not seen, append 0 or remove if too long inactive
            process_history[pid]['gpu_util'].append(0)
            process_history[pid]['gpu_mem_perc'].append(0)
            process_history[pid]['ram'].append(0)
        # Keep only last MAX_SAMPLES
        for key in ['gpu_util', 'gpu_mem_perc', 'ram']:
            process_history[pid][key] = process_history[pid][key][-MAX_SAMPLES:]
        # Remove if all recent are 0
        if all(u == 0 for u in process_history[pid]['gpu_util'][-5:]):
            del process_history[pid]

def analyze_process(pid):
    history = process_history[pid]
    if len(history['gpu_util']) < MIN_SAMPLES:
        return False
    
    avg_gpu_util = np.mean(history['gpu_util'])
    avg_gpu_mem = np.mean(history['gpu_mem_perc'])
    avg_ram = np.mean(history['ram'])
    std_gpu_util = np.std(history['gpu_util'])
    
    # Decision tree logic
    if avg_gpu_util <= GPU_UTIL_THRESHOLD:
        return False
    if avg_gpu_mem <= GPU_MEM_THRESHOLD:
        return False
    if avg_ram > RAM_THRESHOLD or std_gpu_util < STD_DEV_THRESHOLD:
        return True
    return False

def main():
    total_mem = get_total_gpu_memory()
    if total_mem is None:
        print("Unable to get GPU memory. Ensure NVIDIA GPU and drivers are installed.")
        return
    
    print("Starting GPU Cryptojacking Detection Prototype...")
    print("Monitoring for suspicious processes. Press Ctrl+C to stop.")
    
    alerted = set()  # To avoid repeated alerts
    
    try:
        while True:
            collect_metrics(total_mem)
            
            for pid in list(process_history.keys()):
                if analyze_process(pid) and pid not in alerted:
                    name = process_history[pid]['name'] or 'Unknown'
                    print(f"\nALERT: Potential GPU cryptojacker detected!")
                    print(f"Process ID: {pid}")
                    print(f"Process Name: {name}")
                    print("You may terminate it using Task Manager or command: taskkill /PID {pid} /F")
                    alerted.add(pid)
            
            time.sleep(SAMPLE_INTERVAL)
    except KeyboardInterrupt:
        print("\nStopping detection.")

if __name__ == "__main__":
    main()
