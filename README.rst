
A Python library for vADC
=========================

A library for interacting with the REST API of `Brocade vADC <http://www.brocade.com/vadc>`_.

----

To install, either clone from github or "pip install pyvadc"

To use (standalone vTM):

.. code-block:: python

   from pyvadc import Vtm, VtmConfig
   config = VtmConfig("https://vtm1:9070/", "admin", "password")

   vtm = Vtm(config)
   vtm.get_pools()
   ...

To Use with BSD:

.. code-block:: python

   from pyvadc import Bsd, Vtm, BsdConfig
   config = BsdConfig("https://sd1:8100/", "admin", "password")
   bsd = Bsd(config)
   bsd.add_vtm("vtm1", "password", "172.17.0.2", 100, "STM-400_full")
   bsd.get_status("vtm1")

   # We can now manage vTMs by proxying.
   vtm1 = Vtm(config, vtm="vtm1")
   vtm1.get_pools()
   ...

Enjoy!
