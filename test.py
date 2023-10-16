from lib.pydhcp import DhcpOptionCode
from lib.pydhcp.iana import OptionOverload

test_0 = OptionOverload(0)
test_1 = OptionOverload(1)
test_2 = OptionOverload(2)
test_3 = OptionOverload(3)

test = DhcpOptionCode.VENDOR_CLASS_IDENTIFIER.get_type().decode(b'android-dhcp-13')
test2 = test.encode()
pass
