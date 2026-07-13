import logging
import sys

from pydhcp import DhcpListener, log


LOGGER = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
LOGGER.addHandler(handler)
log.LOGGER.setLevel(logging.DEBUG)


if __name__ == "__main__":
    listener = DhcpListener(listen="*", per_interface=True)
    listener.start()
    listener.wait()
