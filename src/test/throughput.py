import requests
import threading
import time

from queue import Queue

# Config
PROXY_URL = "socks5h://localhost:1024"
TARGET_URL = "http://localhost:80"
NUM_USERS = 1024
REQUESTS_PER_USER = 1

proxy = {
    "http": PROXY_URL,
    "https": PROXY_URL
}

results = Queue()

def worker(user_id):
    for i in range(REQUESTS_PER_USER):
        try:
            start = time.time()
            r = requests.get(TARGET_URL, proxies=proxy, timeout=10)
            end = time.time()
            size = len(r.content) / 1024
            t = end - start
            throughput = size / t
            print(f"[User {user_id}] Request {i+1}: {size:.2f} KB in {t:.2f}s ({throughput:.2f} KB/s)")
            results.put(throughput)
        except Exception as e:
            print(f"[User {user_id}] Request {i+1} failed: {e}")
            results.put(0)

threads = []
start_all = time.time()

for uid in range(NUM_USERS):
    t = threading.Thread(target=worker, args=(uid,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

end_all = time.time()
total_time = end_all - start_all

# Gather results
throughputs = []
while not results.empty():
    throughputs.append(results.get())

avg_throughput = sum(throughputs) / len(throughputs)
print(f"\nTotal requests: {len(throughputs)}")
print(f"Total time: {total_time:.2f}s")
print(f"Average throughput: {avg_throughput:.2f} KB/s")

import matplotlib.pyplot as plt
plt.plot(throughputs, marker='o')
plt.title("SOCKS5 Throughput (Concurrent Requests)")
plt.xlabel("Request #")
plt.ylabel("Throughput (KB/s)")
plt.grid(True)
plt.tight_layout()
plt.show()