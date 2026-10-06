import logging
import sys

from pydhcp import DHCPListener

LOGGER = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
LOGGER.addHandler(handler)
logging.getLogger("pydhcp").setLevel(logging.DEBUG)


if __name__ == "__main__":
    # The wildcard hears the broadcasts of every segment; per_interface=True
    # would bind addresses, which hear none on Linux.
    with DHCPListener(listen="*") as listener:
        try:
            listener.serve_forever()
        except KeyboardInterrupt:
            pass
