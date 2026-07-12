# Common DHCP Options

This page shows the typed option workflow: assign native Python values to `DhcpOptions`, let the registered option type do the encoding, and inspect decoded values with `repr()`.

## Single IPv4 option

```python
from pydhcp import DhcpOptions
from pydhcp.enum import DhcpOptionCode

options = DhcpOptions()
options[DhcpOptionCode.SERVER_IDENTIFIER] = "192.0.2.1"
```

## List of IPv4 addresses

```python
from pydhcp import DhcpOptions
from pydhcp.enum import DhcpOptionCode

options = DhcpOptions()
options[DhcpOptionCode.DNS] = ["192.0.2.53", "192.0.2.54"]
```

## Boolean option

```python
from pydhcp import DhcpOptions
from pydhcp.enum import DhcpOptionCode

options = DhcpOptions()
options[DhcpOptionCode.RAPID_COMMIT] = True
```

## Fixed-width integer option

```python
from pydhcp import DhcpOptions
from pydhcp.enum import DhcpOptionCode

options = DhcpOptions()
options[DhcpOptionCode.IP_ADDRESS_LEASE_TIME] = 3600
```

## String option

```python
from pydhcp import DhcpOptions
from pydhcp.enum import DhcpOptionCode

options = DhcpOptions()
options[DhcpOptionCode.HOSTNAME] = "workstation-01"
```

## Classless static route

```python
from ipaddress import ip_network

from pydhcp import DhcpOptions
from pydhcp.enum import DhcpOptionCode
from pydhcp.netutils import IPv4
from pydhcp.optiontype import ClasslessRoute

options = DhcpOptions()
options[DhcpOptionCode.CLASSLESS_STATIC_ROUTE] = ClasslessRoute(
    IPv4("192.0.2.1"),
    ip_network("10.0.0.0/8"),
)
```

## Domain search list

```python
from pydhcp import DhcpOptions
from pydhcp.enum import DhcpOptionCode

options = DhcpOptions()
options[DhcpOptionCode.DOMAIN_SEARCH] = ["example.internal", "lab.example.internal"]
```

## Decoded display

`DhcpOptions.items(decoded=True)` returns typed values, so `repr()` now shows the improved type-specific output.

```python
from ipaddress import ip_network

from pydhcp import DhcpOptions
from pydhcp.enum import DhcpOptionCode
from pydhcp.netutils import IPv4
from pydhcp.optiontype import Boolean, ClasslessRoute

options = DhcpOptions()
options[DhcpOptionCode.RAPID_COMMIT] = True
options[DhcpOptionCode.CLASSLESS_STATIC_ROUTE] = ClasslessRoute(
    IPv4("192.0.2.1"),
    ip_network("10.0.0.0/8"),
)

for code, value in options.items(decoded=True):
    print(code, repr(value))
```
