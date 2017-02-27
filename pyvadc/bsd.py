#!/usr/bin/python

from vadc import Vadc
from vtm import Vtm

class Bsd(Vadc):

    def __init__(self, config, logger=None):

        try:
            host = config['brcd_sd_host']
            user = config['brcd_sd_user']
            passwd = config['brcd_sd_pass']
        except KeyError:
            raise ValueError("brcd_sd_host, brcd_sd_user, and brcd_sd_pass must be configured")

        super(Bsd, self).__init__(host, user, passwd, logger)
        self.version = self._get_api_version("api/tmcm")
        self.baseUrl = host + "api/tmcm/" + self.version

    def _get_vtm_licenses(self):
        url = self.baseUrl + "/license"
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to get licenses: {}, {}".format(res.status_code, res.text))
        licenses = res.json()
        licenses = licenses["children"]
        universal = [int(lic["name"][11:]) for lic in licenses
            if lic["name"].startswith("universal_v")]
        universal.sort(reverse=True)
        legacy = [float(lic["name"][7:]) for lic in licenses
            if lic["name"].startswith("legacy_")]
        legacy.sort(reverse=True)
        order = []
        order += (["universal_v" + str(ver) for ver in universal])
        order += (["legacy_" + str(ver) for ver in legacy])
        return order

    def ping(self):
        url = self.baseUrl + "/ping"
        res = self._get_config(url)
        if res.status_code != 204:
            raise Exception("Ping unsuccessful")
        config = res.json()
        return config["members"]

    def get_cluster_members(self, cluster):
        url = self.baseUrl + "/cluster/" + cluster
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to locate cluster: {}, {}".format(res.status_code, res.text))
        config = res.json()
        return config["members"]

    def get_active_vtm(self, vtms=None, cluster=None):
        if cluster is None and vtms is None:
            raise Exception("Error - You must supply either a list of vTMs or a Cluster ID")
        if cluster is not None and cluster != "":
            vtms = self.get_cluster_members(cluster)
        for vtm in vtms:
            url = self.baseUrl + "/instance/" + vtm + "/tm/"
            res = self._get_config(url)
            if res.status_code == 200:
                return vtm
        return None

    def add_vtm(self, vtm, password, address, bw, fp='STM-400_full'):
        url = self.baseUrl + "/instance/?managed=false"

        if address is None:
            address = vtm

        config = {"bandwidth": bw, "tag": vtm, "owner": "stanley", "stm_feature_pack": fp,
            "rest_address": address + ":9070", "admin_username": "admin", "rest_enabled": False,
            "host_name": address, "management_address": address}

        if password is not None:
            config["admin_password"] = password
            config["rest_enabled"] = True

            # Try each of our available licenses.
            licenses = self._get_vtm_licenses()
            for license in licenses:
                config["license_name"] = license
                res = self._push_config(url, config, "POST")
                if res.status_code == 201:
                    break
        else:
            res = self._push_config(url, config, "POST")

        if res.status_code != 201:
            raise Exception("Failed to add vTM. Response: {}, {}".format(res.status_code, res.text))
        return res.json()

    def del_vtm(self, vtm):
        url = self.baseUrl + "/instance/" + vtm
        config = {"status": "deleted"}
        res = self._push_config(url, config, "POST")
        if res.status_code != 200:
            raise Exception("Failed to del vTM. Response: {}, {}".format(res.status_code, res.text))
        return res.json()

    def get_vtm(self, tag):
        vtm = self._cache_lookup("get_vtm_" + tag)
        if vtm is None:
            url = self.baseUrl + "/instance/" + tag
            res = self._get_config(url)
            if res.status_code != 200:
                raise Exception("Failed to get vTM {}. Response: {}, {}".format(
                    vtm, res.status_code, res.text))
            vtm = res.json()
            self._cache_store("get_vtm_" + tag, vtm)
        return vtm

    def list_vtms(self, full=False, deleted=False, stringify=False):
        instances = self._cache_lookup("list_vtms")
        if instances is None:
            url = self.baseUrl + "/instance/"
            res = self._get_config(url)
            if res.status_code != 200:
                raise Exception("Failed to list vTMs. Response: {}, {}".format(
                    res.status_code, res.text))
            instances = res.json()
            self._cache_store("list_vtms", instances)

        output = []
        for instance in instances["children"]:
            config = self.get_vtm(instance["name"])
            if deleted is False and config["status"] == "Deleted":
                continue
            if full:
                config["name"] = instance["name"]
                output.append(config)
            else:
                out_dict = {k: config[k] for k in ("host_name", "tag", "status",
                    "stm_feature_pack", "bandwidth")}
                out_dict["name"] = instance["name"]
                output.append(out_dict)

        if stringify:
            return json.dumps(output, encoding="utf-8")
        else:
            return output

    def _submit_backup_task(self, vtm=None, cluster_id=None, tag=None):
        if self.version < 2.3:
            raise Exception("You need to be running BSD version 2.5 or newer to perform a backup")
        url = self.baseUrl + "/config/backup/task"
        if cluster_id is None:
            if vtm is None:
                raise Exception("You need to provide with a vTM or Cluster-ID")
            cluster_id = self._get_cluster_for_vtm(cluster)
        config = { "cluster_id": cluster_id, "task_type": "backup restore",
            "task_subtype": "backup now" }
        res = self._push_config(url, config, "POST")
        if res.status_code != 201:
            raise Exception("Failed to create BackUp, Response: {}, {}".format(
                res.status_code, res.text))
        return res.json()

    def get_status(self, vtm=None, stringify=False):
        instances = self._cache_lookup("get_status")
        if instances is None:
            url = self.baseUrl + "/monitoring/instance"
            res = self._get_config(url)
            if res.status_code != 200:
                raise Exception("Failed get Status. Result: {}, {}".format(
                    res.status_code, res.text))

            instances = res.json()
            self._cache_store("get_status", instances)

        if vtm is not None:
            for instance in instances:
                if instance["tag"] != vtm and instance["name"] != vtm:
                    instances.remove(instance)

        if stringify:
            return json.dumps(instances, encoding="utf-8")
        else:
            return instances

    def get_errors(self, stringify=False):
        instances = self.get_status()
        errors = {}
        for instance in instances:
            error = {}
            self._debug(instance)
            if instance["id_health"]["alert_level"] != 1:
                error["id_health"] = instance["id_health"]
            if instance["rest_access"]["alert_level"] != 1:
                error["rest_access"] = instance["rest_access"]
            if instance["licensing_activity"]["alert_level"] != 1:
                error["licensing_activity"] = instance["licensing_activity"]
            if instance["traffic_health"]["error_level"] != "ok":
                error["traffic_health"] = instance["traffic_health"]
            if len(error) != 0:
                error["tag"] = instance["tag"]
                error["name"] = instance["name"]
                if "traffic_health" in error:
                    if "virtual_servers" in error["traffic_health"]:
                        del error["traffic_health"]["virtual_servers"]
                errors[instance["name"]] = error

        if stringify:
            return json.dumps(errors, encoding="utf-8")
        else:
            return errors

    def get_monitor_intervals(self, setting=None):
        intervals = self._cache_lookup("get_monitor_intervals")
        if intervals is None:
            url = self.baseUrl + "/settings/monitoring"
            res = self._get_config(url)
            if res.status_code != 200:
                raise Exception("Failed to get Monitoring Intervals. Result: {}, {}".format(
                    res.status_code, res.text))

            intervals = res.json()
            self._cache_store("get_monitor_intervals", intervals)

        if setting is not None:
            if setting not in intervals:
                raise Exception("Setting: {} does not exist.".format(setting))
            return intervals[setting]
        return intervals

    def get_bandwidth(self, vtm=None, stringify=False):
        instances = self.get_status(vtm)
        bandwidth = {}
        for instance in instances:
            config = self.get_vtm(instance["name"])
            tag = config["tag"]
            # Bytes/Second
            if "throughput_out" in instance:
                current = (instance["throughput_out"] / 1000000.0) * 8
            else:
                current = 0.0
            # Mbps
            assigned = config["bandwidth"]
            # Bytes/Second
            if "metrics_peak_throughput" in config:
                peak = (config["metrics_peak_throughput"] / 1000000.0) * 8
            else:
                peak = 0.0
            bandwidth[instance["name"]] = {"tag": tag, "current": current,
                "assigned": assigned, "peak": peak}

        if stringify:
            return json.dumps(bandwidth, encoding="utf-8")
        else:
            return bandwidth

    def set_bandwidth(self, vtm, bw):
        url = self.baseUrl + "/instance/" + vtm
        config = {"bandwidth": bw}
        res = self._push_config(url, config)
        if res.status_code != 200:
            raise Exception("Failed to set Bandwidth. Result: {}, {}".format(
                res.status_code, res.text))
        config = res.json()
        return config
