import logging
import sys
LOGGER = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
LOGGER.addHandler(handler)
import pathlib
_SRC = pathlib.Path(__file__).parent.parent / "src"
sys.path.insert(0, _SRC.as_posix())

from pydhcp import DhcpListener, log
log.LOGGER.setLevel(logging.DEBUG)

dhcpd = DhcpListener(listen="*", per_interface=True)
dhcpd.start()
dhcpd.wait()
