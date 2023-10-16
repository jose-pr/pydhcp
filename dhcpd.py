import logging , sys 
LOGGER = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
LOGGER.addHandler(handler)

from lib.pydhcp import DhcpServer, log
log.LOGGER.setLevel(logging.DEBUG)

dhcpd = DhcpServer()
dhcpd.start()
dhcpd.wait()
pass