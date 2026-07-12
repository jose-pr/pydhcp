import timeit
import sys
import pathlib
from datetime import timedelta

# Ensure src/ is in the import path
SRC_DIR = pathlib.Path(__file__).parent.parent / "src"
sys.path.insert(0, SRC_DIR.as_posix())

from pydhcp.message import DhcpMessage
from pydhcp.enum import OpCode, HardwareAddressType, Flags, DhcpOptionCode, DhcpMessageType
from pydhcp.netutils import IPv4
from pydhcp.options import DhcpOptions

def build_benchmark_payload() -> bytes:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray([DhcpMessageType.DHCPDISCOVER.value])
    options[DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray([1, 0, 17, 34, 51, 68, 85])
    options[DhcpOptionCode.PARAMETER_REQUEST_LIST] = bytearray([1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252])

    msg = DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x3903F326,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4('0.0.0.0'),
        yiaddr=IPv4('0.0.0.0'),
        siaddr=IPv4('0.0.0.0'),
        giaddr=IPv4('0.0.0.0'),
        chaddr=b'\x00\x11\x22\x33\x44\x55',
        sname='',
        file='',
        options=options
    )
    return bytes(msg.encode())

PAYLOAD_BYTES = build_benchmark_payload()

def run_benchmarks(iterations: int = 10000):
    print(f"--- Running DHCP Packet Parsing Benchmarks ({iterations:,} iterations) ---")
    
    # 1. Decode Benchmark
    # We use memoryview(PAYLOAD_BYTES) as is typically done in the listener
    payload_mv = memoryview(PAYLOAD_BYTES)
    
    def test_decode():
        DhcpMessage.decode(payload_mv)
        
    decode_time = timeit.timeit(test_decode, number=iterations)
    decode_ops_per_sec = iterations / decode_time
    print(f"Decode: {decode_time:.4f} seconds ({decode_ops_per_sec:.1f} ops/sec)")
    
    # 2. Encode Benchmark
    msg = DhcpMessage.decode(payload_mv)
    
    def test_encode():
        msg.encode()
        
    encode_time = timeit.timeit(test_encode, number=iterations)
    encode_ops_per_sec = iterations / encode_time
    print(f"Encode: {encode_time:.4f} seconds ({encode_ops_per_sec:.1f} ops/sec)")
    
    # Return stats for documentation
    return {
        "iterations": iterations,
        "decode_time": decode_time,
        "decode_ops": decode_ops_per_sec,
        "encode_time": encode_time,
        "encode_ops": encode_ops_per_sec,
    }


if __name__ == "__main__":
    run_benchmarks()
