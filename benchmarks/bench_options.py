import timeit
import sys
import pathlib

# Ensure src/ is in the import path
SRC_DIR = pathlib.Path(__file__).parent.parent / "src"
sys.path.insert(0, SRC_DIR.as_posix())

from pydhcp.options import DhcpOptions
from pydhcp.enum import DhcpOptionCode
from pydhcp.netutils import IPv4
from pydhcp.lease import InMemoryLeaseBackend

def build_options_payload(option_count: int) -> bytearray:
    opts = DhcpOptions()
    for i in range(1, option_count + 1):
        opts[i] = bytearray([192, 168, 1, i])
    return opts.encode()

def test_memory_usage():
    backend = InMemoryLeaseBackend()
    options = DhcpOptions()
    for i in range(1000):
        client_id = f"client-{i}"
        ip = IPv4("192.168.1.1")
        backend.allocate(client_id, ip, 3600, options)

def run_benchmarks(iterations: int = 10000):
    print(f"--- Running DHCP Options & Memory Benchmarks ({iterations:,} iterations) ---")
    
    p0 = memoryview(build_options_payload(0))
    p5 = memoryview(build_options_payload(5))
    p20 = memoryview(build_options_payload(20))
    
    t0 = timeit.timeit(lambda: DhcpOptions().decode(p0), number=iterations)
    t5 = timeit.timeit(lambda: DhcpOptions().decode(p5), number=iterations)
    t20 = timeit.timeit(lambda: DhcpOptions().decode(p20), number=iterations)
    
    print(f"Decode with 0 options:  {t0:.4f}s ({iterations/t0:.1f} ops/sec)")
    print(f"Decode with 5 options:  {t5:.4f}s ({iterations/t5:.1f} ops/sec)")
    print(f"Decode with 20 options: {t20:.4f}s ({iterations/t20:.1f} ops/sec)")
    
    opts = DhcpOptions()
    opts[DhcpOptionCode.SUBNET_MASK] = IPv4("255.255.255.0")
    
    def round_trip():
        encoded = opts.encode()
        decoded = DhcpOptions()
        decoded.decode(memoryview(encoded))
        
    trt = timeit.timeit(round_trip, number=iterations)
    print(f"Round-trip encode/decode: {trt:.4f}s ({iterations/trt:.1f} ops/sec)")
    
    t_mem = timeit.timeit(test_memory_usage, number=100)
    print(f"1000 lease allocations (x100 reps): {t_mem:.4f}s ({100/t_mem:.1f} reps/sec)")

if __name__ == "__main__":
    run_benchmarks()
