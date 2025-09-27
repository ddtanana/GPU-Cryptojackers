GPU Cryptojacking Detection Prototype
Overview
This is a prototype program for detecting GPU cryptojacking based on the research paper "Behavior-Based Detection of GPU Cryptojacking" by Dmitry D. Tanana. It monitors GPU-utilizing processes on Windows systems with NVIDIA GPUs, using metrics like GPU utilization, GPU memory usage, RAM consumption, and the standard deviation of GPU utilization to identify potential cryptominers.
The detection logic follows a decision tree inspired by the paper's algorithm.

It runs continuously, alerting on suspicious processes.
Requirements

Python 3.x
NVIDIA GPU with drivers installed (nvidia-smi must be available)
Libraries: psutil, numpy (install via pip install psutil numpy)

Usage

Save the script as gpu_cryptojack_detector.py.
Run it with administrative privileges: python gpu_cryptojack_detector.py.
The program will monitor and print alerts for detected processes.
To terminate a detected process, use Task Manager or taskkill /PID <pid> /F.

Limitations

Tested only in controlled environments; may have false positives (e.g., benchmarks like PassMark).
Does not handle stealth techniques like varying GPU load.
For Windows only, requires NVIDIA hardware.
Prototype: Not for production use without further testing.

Credits
Based on research by Dmitry D. Tanana, Ural Federal University.
