"""Bounded network tools for explicitly authorized browser assessments."""
import socket
import threading
import time
from queue import Empty, Queue
from uuid import uuid4

import requests


class PayloadRequestError(Exception):
    pass


def send_test_payload(target_url, method, parameter, payload, timeout=10):
    """Send one same-origin test request without cookies or redirects."""
    started = time.monotonic()
    try:
        if method == "GET":
            response = requests.get(target_url, params={parameter: payload}, timeout=timeout,
                                    verify=True, allow_redirects=False)
        elif method == "POST_FORM":
            response = requests.post(target_url, data={parameter: payload}, timeout=timeout,
                                     verify=True, allow_redirects=False)
        elif method == "POST_JSON":
            response = requests.post(target_url, json={parameter: payload}, timeout=timeout,
                                     verify=True, allow_redirects=False)
        else:
            raise ValueError("Unsupported payload request method")
    except requests.RequestException as error:
        raise PayloadRequestError(str(error)) from error
    return {
        "method": method,
        "request_url": response.request.url,
        "status_code": response.status_code,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        "response_length": len(response.content),
        "response_excerpt": response.text[:1000],
        "response_headers": dict(response.headers),
        "redirect_location": response.headers.get("Location"),
    }


class PortScanManager:
    """Runs one bounded TCP-connect scan at a time in background workers."""

    def __init__(self, workers=128):
        self.workers = workers
        self.jobs = {}
        self.lock = threading.Lock()

    def start(self, host, start_port=1, end_port=65535, timeout_ms=200):
        if not 1 <= start_port <= end_port <= 65535:
            raise ValueError("Port range must be between 1 and 65535")
        if not 50 <= timeout_ms <= 2000:
            raise ValueError("Timeout must be between 50 and 2000 milliseconds")
        with self.lock:
            if any(job["status"] in {"queued", "running"} for job in self.jobs.values()):
                raise ValueError("Another port scan is already running")
            job_id = uuid4().hex
            self.jobs[job_id] = {
                "id": job_id, "host": host, "status": "queued",
                "start_port": start_port, "end_port": end_port,
                "total": end_port - start_port + 1, "scanned": 0,
                "open_ports": [], "started_at": None, "finished_at": None,
                "error": None,
            }
            self._trim_jobs()
        threading.Thread(target=self._run, args=(job_id, timeout_ms / 1000), daemon=True).start()
        return self.get(job_id)

    def get(self, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return None
            result = dict(job)
            result["open_ports"] = [dict(item) for item in job["open_ports"]]
            result["progress"] = round(job["scanned"] / job["total"] * 100, 1)
            return result

    def _trim_jobs(self):
        completed = [key for key, job in self.jobs.items()
                     if job["status"] not in {"queued", "running"}]
        for key in completed[:-19]:
            self.jobs.pop(key, None)

    def _run(self, job_id, timeout):
        job = self.jobs[job_id]
        try:
            addresses = socket.getaddrinfo(job["host"], None, type=socket.SOCK_STREAM)
            if not addresses:
                raise OSError("Hostname did not resolve")
            family, _, _, _, sockaddr = addresses[0]
            ip = sockaddr[0]
            ports = Queue()
            for port in range(job["start_port"], job["end_port"] + 1):
                ports.put(port)
            with self.lock:
                job["status"] = "running"
                job["started_at"] = time.time()
                job["resolved_address"] = ip

            def worker():
                while True:
                    try:
                        port = ports.get_nowait()
                    except Empty:
                        return
                    is_open = False
                    sock = socket.socket(family, socket.SOCK_STREAM)
                    try:
                        sock.settimeout(timeout)
                        address = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
                        is_open = sock.connect_ex(address) == 0
                    except OSError:
                        is_open = False
                    finally:
                        sock.close()
                    with self.lock:
                        job["scanned"] += 1
                        if is_open:
                            try:
                                service = socket.getservbyport(port, "tcp")
                            except OSError:
                                service = "unknown"
                            job["open_ports"].append({"port": port, "service": service})

            threads = [threading.Thread(target=worker, daemon=True)
                       for _ in range(min(self.workers, job["total"]))]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            with self.lock:
                job["open_ports"].sort(key=lambda item: item["port"])
                job["status"] = "completed"
                job["finished_at"] = time.time()
        except Exception as error:
            with self.lock:
                job["status"] = "failed"
                job["error"] = str(error)
                job["finished_at"] = time.time()
