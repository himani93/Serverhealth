import logging

from pyzabbix import ZabbixAPI
from pyzabbix.api import ZabbixAPIException
from exceptions import *

logger = logging.getLogger(__name__)


class ServerHealth(object):

    def __init__(self, url, user, password, templates):
        self.monitoring_app = ZabbixAPI(url=url, password=password, user=user)
        self.templates = templates

    def register_user(self, first_name, last_name, username, password, usergroup_name):
        try:
            usergroup = self.monitoring_app.usergroup.create(name=usergroup_name)
            usergroup_id = usergroup["usrgrpids"][0]

            user = self.monitoring_app.user.create(name=first_name, surname=last_name, type=1, alias=username,
                                                   passwd=password, usrgrps=usergroup_id)

            user_id = user["userids"][0]
            logger.debug("User {} id at monitoring portal is {}".format(username, user_id))
        except ZabbixAPIException as e:
            raise ServerHealthException("Error registering user on monitoring portal: {}".format(e))

        return user_id

    def register_node(self, hostname, user_id, host_group_name):
        agent_interfaces = [
            {
                "type": 1,
                "main": 1,
                "useip": 1,
                "ip": hostname,
                "dns": "",
                "port": "10050"
            }
        ]

        try:
            host_group = self.monitoring_app.hostgroup.get(filter={"name": host_group_name})
        except ZabbixAPIException as e:
            raise ServerHealthException("Error retrieving host group: {}".format(e))

        if not host_group:
            try:
                host_group = self.monitoring_app.hostgroup.create(name=host_group_name)
            except ZabbixAPIException as e:
                ServerHealthException("Error registering host group: {}".format(e))

        if type(host_group) is list:
            hostgroup_id = host_group[0].get("groupid", "")
        else:
            hostgroup_id = host_group.get("groupids")[0]

        # TODO: Check if permissions are not added to user group if customer not able to fetch data? or this only effects in notification
        try:
            self._update_usergroup_permissions(usergrpid="", userid=user_id, hostgrp_id=hostgroup_id)
        except ZabbixAPIException as e:
            logger.error("Error updating user group permissions: {}".format(e))

        try:
            templates = self.monitoring_app.template.get(filter={"name": self.templates})
        except ZabbixAPIException as e:
            raise ServerHealthException("Error retrieving monitoring templates: {}".format(e))
        else:
            if not templates:
                raise ServerHealthException("Monitoring templates: {} not found.".format(templates))

        if type(host_group) is not list:
            host_group = [{"groupid": hostgroup_id}]

        try:
            host = self.monitoring_app.host.create(host=hostname, groups=host_group, interfaces=agent_interfaces,
                                                   templates=templates)
        except ZabbixAPIException as e:
            raise ServerHealthException("Error registering node for monitoring: {}".format(e))

        return host["hostids"][0]

    def update_user(self, userid, password):
        updated = False

        try:
            self.monitoring_app.user.update(userid=userid, passwd=password)
        except ZabbixAPIException as e:
            raise ServerHealthException("Error updating user password on monitoring portal: {}".format(e))
        else:
            updated = True

        return updated

    def deregister_node(self, host_id):
        deregistered = False

        try:
            self.monitoring_app.host.delete(host_id)
        except ZabbixAPIException as e:
            raise ServerHealthException("Error de-registering node: {}".format(e))
        else:
            deregistered = True

        return deregistered

    def _get_usergroup(self, usrgrpid="", userid=""):
        try:
            usergroup = self.monitoring_app.usergroup.get(usergrpids=usrgrpid, userids=userid, selectRights="extend")
        except ZabbixAPIException as e:
            raise ServerHealthException("Error retrieving user group: {}".format(e))

        return usergroup

    def _update_usergroup_permissions(self, usergrpid, userid, hostgrp_id):
        usergroup = self._get_usergroup(usergrpid, userid)
        if not usergroup:
            raise ServerHealthException("User group not found for userid: {}.".format(userid))

        usergroup_id = usergroup[0].get("usrgrpid", "")
        permissions = usergroup[0].get("rights", [])

        hostgroup_permission = {"id": hostgrp_id, "permission": 2}
        # TODO: check if permission for host group exists in user group
        permissions.append(hostgroup_permission)

        try:
            updated_user_group = self.monitoring_app.usergroup.update(usrgrpid=usergroup_id, rights=permissions)
        except ZabbixAPIException as e:
            raise ServerHealthException("Error updating usergroup permissions: {}".format(e))

        return updated_user_group
