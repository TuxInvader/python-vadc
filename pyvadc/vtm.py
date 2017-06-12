#!/usr/bin/python

from vadc import Vadc

import json

class Vtm(Vadc):

    def __init__(self, config, logger=None, vtm=None):

        try:
            self._proxy = config['brcd_sd_proxy']
            if self._proxy:
                if vtm is None:
                    raise ValueError("You must set vtm, when using SD Proxy")
                host = config['brcd_sd_host']
                user = config['brcd_sd_user']
                passwd = config['brcd_sd_pass']
            else:
                host = config['brcd_vtm_host']
                user = config['brcd_vtm_user']
                passwd = config['brcd_vtm_pass']
        except KeyError:
            raise ValueError("You must set key brcd_sd_proxy, and either " +
                "brcd_sd_[host|user|pass] or brcd_vtm_[host|user|pass].")

        self.vtm = vtm
        self.bsdVersion = None
        super(Vtm, self).__init__(host, user, passwd, logger)
        if self._proxy:
            self.bsdVersion = self._get_api_version("api/tmcm")
            self.version = self._get_api_version(
                "api/tmcm/{}/instance/{}/tm".format(self.bsdVersion, vtm))
            self.baseUrl = host + "api/tmcm/{}".format(self.bsdVersion) + \
                "/instance/{}/tm/{}".format(vtm, self.version)
        else:
            self.version = self._get_api_version("api/tm")
            self.baseUrl = host + "api/tm/{}".format(self.version)
        self.configUrl = self.baseUrl + "/config/active"
        self.statusUrl = self.baseUrl + "/status/local_tm"

    def _get_node_table(self, name):
        url = self.configUrl + "/pools/" + name
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to get pool. Result: {}, {}".format(res.status_code, res.text))

        config = res.json()
        return config["properties"]["basic"]["nodes_table"]

    def _get_single_config(self, obj_type, name):
        url = self.configUrl + "/" + obj_type + "/" + name
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to get " + obj_type + " Configuration." +
                " Result: {}, {}".format(res.status_code, res.text))
        return res.json()

    def _get_multiple_configs(self, obj_type, names=[]):
        url = self.configUrl + "/" + obj_type + "/"
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to list " + obj_type +
                ". Result: {}, {}".format(res.status_code, res.text))
        listing = res.json()["children"]
        output = {}
        for obj in [obj["name"] for obj in listing]:
            if len(names) > 0 and (obj not in names):
                continue
            output[obj] = self._get_single_config(obj_type, obj)
        return output

    def _set_single_config(self, obj_type, name, config):
        url = self.configUrl + "/" + obj_type + "/" + name
        res = self._push_config(url, config)
        if res.status_code != 200:
            raise Exception("Failed to set " + obj_type + ". Result: {}, {}".format(
                res.status_code, res.text))
        return res

    def _get_vs_rules(self, name):
        config = self._get_single_config("virtual_servers", name)
        rules = {k: config["properties"]["basic"][k] for k in
                ("request_rules", "response_rules", "completionrules")}
        return rules

    def _set_vs_rules(self, name, rules):
        config = {"properties": {"basic": rules}}
        res = self._set_single_config("virtual_servers", name, config)
        if res.status_code != 200:
            raise Exception("Failed set VS Rules. Result: {}, {}".format(res.status_code, res.text))

    def insert_rule(self, vsname, rulename, insert=True):
        rules = self._get_vs_rules(vsname)
        if insert:
            if rulename in rules["request_rules"]:
                raise Exception("Rule {} already in vserver {}".format(rulename, vsname))
            rules["request_rules"].insert(0, rulename)
        else:
            if rulename not in rules["request_rules"]:
                raise Exception("Rule {} already in vserver {}".format(rulename, vsname))
            rules["request_rules"].remove(rulename)
        self._set_vs_rules(vsname, rules)

    def upload_rule(self, rulename, ts_file):
        url = self.configUrl + "/rules/" + rulename
        res = self._upload_raw_binary(url, ts_file)
        if res.status_code != 201 and res.status_code != 204:
            raise Exception("Failed to upload rule." +
                " Result: {}, {}".format(res.status_code, res.text))

    def enable_maintenance(self, vsname, rulename="maintenance", enable=True):
        self.insert_rule(vsname, rulename, enable)

    def get_pool_nodes(self, name):
        nodeTable = self._get_node_table(name)
        nodes = {"active": [], "disabled": [], "draining": []}
        for node in nodeTable:
            if node["state"] == "active":
                nodes["active"].append(node["node"])
            elif node["state"] == "disabled":
                nodes["disabled"].append(node["node"])
            elif node["state"] == "draining":
                nodes["draining"].append(node["node"])
            else:
                self.logger.warn("Unknown Node State: {}".format(node["state"]))

        return nodes

    def set_pool_nodes(self, name, active, draining, disabled):
        url = self.configUrl + "/pools/" + name
        nodeTable = []
        if active is not None and active:
            nodeTable.extend( [{"node": node, "state": "active"} for node in active] )
        if draining is not None and draining:
            nodeTable.extend( [{"node": node, "state": "draining"} for node in draining] )
        if disabled is not None and disabled:
            nodeTable.extend( [{"node": node, "state": "disabled"} for node in disabled] )
        config = {"properties": {"basic": {"nodes_table": nodeTable }}}
        res = self._push_config(url, config)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to set pool nodes. Result: {}, {}".format(res.status_code, res.text))

    def drain_nodes(self, name, nodes, drain=True):
        url = self.configUrl + "/pools/" + name
        nodeTable = self._get_node_table(name)
        for entry in nodeTable:
            if entry["node"] in nodes:
                if drain:
                    entry["state"] = "draining"
                else:
                    entry["state"] = "active"

        config = {"properties": {"basic": {"nodes_table": nodeTable}}}
        res = self._push_config(url, config)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add pool. Result: {}, {}".format(res.status_code, res.text))

    def add_pool(self, name, nodes, algorithm, persistence, monitors, extra=None):
        url = self.configUrl + "/pools/" + name

        nodeTable = []
        for node in nodes:
            nodeTable.append({"node": node, "state": "active"})

        config = {"properties": {"basic": {"nodes_table": nodeTable}, "load_balancing": {}}}

        if monitors is not None:
            config["properties"]["basic"]["monitors"] = monitors

        if persistence is not None:
            config["properties"]["basic"]["persistence_class"] = persistence

        if algorithm is not None:
            config["properties"]["load_balancing"]["algorithm"] = algorithm

        res = self._push_config(url, config, extra=extra)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add pool. Result: {}, {}".format(res.status_code, res.text))

    def del_pool(self, name):
        url = self.configUrl + "/pools/" + name
        res = self._del_config(url)
        if res.status_code != 204:
            raise Exception("Failed to del pool. Result: {}, {}".format(res.status_code, res.text))

    def get_pool(self, name):
        return self._get_single_config("pools", name)

    def get_pools(self, names=[]):
        return self._get_multiple_configs("pools", names)

    def add_vserver(self, name, pool, tip, port, protocol, extra=None):
        url = self.configUrl + "/virtual_servers/" + name
        config = {"properties": {"basic": {"pool": pool, "port": port, "protocol": protocol,
            "listen_on_any": False, "listen_on_traffic_ips": [tip], "enabled": True}}}

        res = self._push_config(url, config, extra=extra)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add VS. Result: {}, {}".format(res.status_code, res.text))

    def del_vserver(self, name):
        url = self.configUrl + "/virtual_servers/" + name
        res = self._del_config(url)
        if res.status_code != 204:
            raise Exception("Failed to del VS. Result: {}, {}".format(res.status_code, res.text))

    def get_vserver(self, name):
        return self._get_single_config("virtual_servers", name)

    def get_vservers(self, names=[]):
        return self._get_multiple_configs("virtual_servers", names)

    def add_tip(self, name, vtms, addresses, extra=None):
        url = self.configUrl + "/traffic_ip_groups/" + name

        config = {"properties": {"basic": {"ipaddresses": addresses,
            "machines": vtms, "enabled": True}}}

        res = self._push_config(url, config, extra=extra)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add TIP. Result: {}, {}".format(res.status_code, res.text))

    def del_tip(self, name):
        url = self.configUrl + "/traffic_ip_groups/" + name
        res = self._del_config(url)
        if res.status_code != 204:
            raise Exception("Failed to del TIP. Result: {}, {}".format(res.status_code, res.text))

    def get_tip(self, name):
        return self._get_single_config("traffic_ip_groups", name)

    def get_tips(self, names=[]):
        return self._get_multiple_configs("traffic_ip_groups", names)

    def add_server_cert(self, name, public, private):
        url = self.configUrl + "/ssl/server_keys/" + name

        public = public.replace("\\n", "\n")
        private = private.replace("\\n", "\n")

        config = {"properties": {"basic": {"public": public, "private": private}}}

        res = self._push_config(url, config)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add Server Certificate." +
                " Result: {}, {}".format(res.status_code, res.text))

    def del_server_cert(self, name):
        url = self.configUrl + "/ssl/server_keys/" + name
        res = self._del_config(url)
        if res.status_code != 204:
            raise Exception("Failed to delete Server Certificate." +
                " Result: {}, {}".format(res.status_code, res.text))

    def enable_ssl_offload(self, name, cert="", on=True, xproto=False, headers=False):
        url = self.configUrl + "/virtual_servers/" + name
        config = {"properties": {"basic": {"ssl_decrypt": on, "add_x_forwarded_proto": xproto},
            "ssl": {"add_http_headers": headers, "server_cert_default": cert}}}

        res = self._push_config(url, config)
        if res.status_code != 200:
            raise Exception("Failed to configure SSl Offload on {}.".format(name) +
                " Result: {}, {}".format(res.status_code, res.text))

    def enable_ssl_encryption(self, name, on=True, verify=False):
        url = self.configUrl + "/pools/" + name
        config = {"properties": {"ssl": {"enable": on, "strict_verify": verify}}}

        res = self._push_config(url, config)
        if res.status_code != 200:
            raise Exception("Failed to configure SSl Encryption on {}.".format(name) +
                " Result: {}, {}".format(res.status_code, res.text))

    def add_session_persistence(self, name, method, cookie=None):
        types = ["ip", "universal", "named", "transparent", "cookie", "j2ee", "asp", "ssl"]
        if method not in types:
            raise Exception("Failed to add SP Class. Invalid method: {}".format(method) +
                "Must be one of: {}".format(types))
        if method == "cookie" and cookie is None:
            raise Exception("Failed to add SP Class. You must provide a cookie name.")

        if cookie is None:
            cookie = ""

        url = self.configUrl + "/persistence/" + name
        config = {"properties": {"basic": {"type": method, "cookie": cookie}}}

        res = self._push_config(url, config)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add Session Persistence Class" +
                " Result: {}, {}".format(res.status_code, res.text))

    def del_session_persistence(self, name):
        url = self.configUrl + "/persistence/" + name
        res = self._del_config(url)
        if res.status_code != 204:
            raise Exception("Failed to delete Session Persistence Class." +
                " Result: {}, {}".format(res.status_code, res.text))

    def add_dns_zone(self, name, origin, zonefile):
        url = self.configUrl + '/dns_server/zones/' + name
        config = {"properties": {"basic": {"zonefile": zonefile, "origin": origin}}}
        res = self._push_config(url, config)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add dns zone" +
                    " Result: {}, {}".format(res.status_code, res.text))

    def add_glb_location(self, name, longitude, latitude, location_id):
        my_location_id = 1
        if location_id is not None:
            my_location_id = location_id
        else:
            # if location_id is not set, we'll have to find one
            url = self.configUrl + '/locations/'
            res = self._get_config(url)
            if res.status_code != 200:
                raise Exception("Failed to get location list: {}, {}".format(res.status_code, res.text))

            location_list = res.json()['children']
            for location in location_list:
                url = self.configUrl + '/locations/' + location['name']
                res = self._get_config(url)
                tmp = res.json()["properties"]["basic"]["id"]
                if tmp > my_location_id:
                    my_location_id = tmp

            # we need to pick up the next one available
            my_location_id = my_location_id + 1

        url = self.configUrl + '/locations/' + name
        config = json.loads('{"properties": {"basic": {"type": "glb", "longitude":' + longitude + ', "latitude": ' + latitude + ', "id": ' + str(my_location_id) + '}}}', parse_float = float)
        res = self._push_config(url, config)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add GLB location" +
                    " Result: {}, {}".format(res.status_code, res.text))

    def list_backups(self):
        if self.version < 3.9:
            raise Exception("Backups require vTM 11.0 or newer")
        url = self.statusUrl + "/backups/full" 
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to get Backup Listing." +
                " Result: {}, {}".format(res.status_code, res.text))
        listing = res.json()["children"]
        output = {}
        for backup in [backup["name"] for backup in listing]:
            url = self.statusUrl + "/backups/full/" + backup
            res = self._get_config(url)
            if res.status_code == 200:
                out = res.json()
                output[backup] = out["properties"]["backup"]
        return output

    def create_backup(self, name, description):
        if self.version < 3.9:
            raise Exception("Backups require vTM 11.0 or newer")
        url = self.statusUrl + "/backups/full/" + name
        description="" if description is None else description
        config = {"properties": {"backup": {"description": description }}}
        res = self._push_config(url, config)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to create Backup." +
                " Result: {}, {}".format(res.status_code, res.text))

    def restore_backup(self, name):
        if self._proxy and self.bsdVersion < 2.4:
            raise Exception("Backup restoration requires BSD Version 2.6 when proxying.")
        if self.version < 3.9:
            raise Exception("Backups require vTM 11.0 or newer")
        url = self.statusUrl + "/backups/full/" + name +"?restore"
        config = {"properties": {}}
        res = self._push_config(url, config)
        if res.status_code != 200:
            raise Exception("Failed to create Backup." +
                " Result: {}, {}".format(res.status_code, res.text))
        return res.json()

    def delete_backup(self, name):
        if self.version < 3.9:
            raise Exception("Backups require vTM 11.0 or newer")
        url = self.statusUrl + "/backups/full/" + name
        res = self._del_config(url)
        if res.status_code != 204:
            raise Exception("Failed to delete Backup." +
                " Result: {}, {}".format(res.status_code, res.text))

    def get_backup(self, name, b64=True):
        if self.version < 3.9:
            raise Exception("Backups require vTM 11.0 or newer")
        url = self.statusUrl + "/backups/full/" + name
        headers = {"Accept": "application/x-tar"}
        res = self._get_config(url, headers=headers)
        if res.status_code != 200:
            raise Exception("Failed to download Backup." +
                " Result: {}, {}".format(res.status_code, res.text))
        backup = b64encode(res.content) if b64 else res.content
        return backup

    def upload_backup(self, name, backup):
        if self.version < 3.9:
            raise Exception("Backups require vTM 11.0 or newer")
        url = self.statusUrl + "/backups/full/" + name
        res = self._push_config(url, backup, ct="application/x-tar")
        if res.status_code != 201 and res.status_code != 204:
            raise Exception("Failed to upload Backup." +
                " Result: {}, {}".format(res.status_code, res.text))

    def upload_extra_file(self, name, filename):
        url = self.configUrl + "/extra_files/" + name
        res = self._upload_raw_binary(url, filename)
        if res.status_code != 201 and res.status_code != 204:
            raise Exception("Failed to upload file." +
                " Result: {}, {}".format(res.status_code, res.text))

    def upload_dns_zone_file(self, name, filename):
        url = self.configUrl + "/dns_server/zone_files/" + name
        res = self._upload_raw_binary(url, filename)
        if res.status_code != 201 and res.status_code != 204:
            raise Exception("Failed to upload file." +
                " Result: {}, {}".format(res.status_code, res.text))

    def upload_action_program(self, name, filename):
        url = self.configUrl + "/action_programs/" + name
        res = self._upload_raw_binary(url, filename)
        if res.status_code != 201 and res.status_code != 204:
            raise Exception("Failed to upload program." +
                " Result: {}, {}".format(res.status_code, res.text))

    def add_action_program(self, name, program, arguments):
        config = {"properties": {"basic": {"type": "program"}, "program": {"arguments": arguments, "program": program}}}
        url = self.configUrl + "/actions/" + name
        res = self._push_config(url, config)
        if res.status_code != 200 and res.status_code != 201:
            raise Exception("Failed to add action." +
                " Result: {}, {}".format(res.status_code, res.text))

    def get_event_type(self, name):
        url = self.configUrl + "/event_types/" + name
        res = self._get_config(url)
        if res.status_code == 404:
            return None
        elif res.status_code != 200:
            raise Exception("Failed to get event." +
                " Result: {}, {}".format(res.status_code, res.text))
        return res.json()

    def add_event_type_action(self, event, action):
        url = self.configUrl + "/event_types/" + event
        config = self.get_event_type(event)
        if config is None:
            return False
        entries = config["properties"]["basic"]["actions"]
        if action in entries:
            return True
        entries.append(action)
        res = self._push_config(url, config)
        if res.status_code != 200:
            raise Exception("Failed to Set Action: {}".format(action) +
                " for Event: {}.".format(event) +
                " Result: {}, {}".format(res.status_code, res.text))

    def set_global_settings(self, settings=None):
        if settings is None:
            return

        url = self.configUrl + "/global_settings"
        jsonsettings = json.loads(settings, encoding="utf-8")

        res = self._push_config(url, jsonsettings)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to set global settings. Result: {}, {}".format(res.status_code, res.text))

