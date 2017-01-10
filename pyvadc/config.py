#!/usr/bin/python

from . import vadc


class VtmConfig(dict):

    def __init__(self, host, user, passwd):
        super(VtmConfig,self).__init__()
        self["brcd_sd_proxy"] = False
        self["brcd_vtm_host"] = host
        self["brcd_vtm_user"] = user
        self["brcd_vtm_pass"] = passwd

class BsdConfig(dict):    

    def __init__(self, host, user, passwd):
        super(BsdConfig,self).__init__()
        self["brcd_sd_proxy"] = True
        self["brcd_sd_host"] = host
        self["brcd_sd_user"] = user
        self["brcd_sd_pass"] = passwd

