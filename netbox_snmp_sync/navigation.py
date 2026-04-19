from netbox.plugins.navigation import PluginMenu, PluginMenuButton, PluginMenuItem

menu = PluginMenu(
    label="SNMP Sync",
    groups=(
        (
            "Discovery",
            (
                PluginMenuItem(
                    link="plugins:netbox_snmp_sync:synclog_list",
                    link_text="Sync Logs",
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_snmp_sync:synclog_list",
                            title="View all sync logs",
                            icon_class="mdi mdi-history",
                        ),
                    ),
                ),
                PluginMenuItem(
                    link="plugins:netbox_snmp_sync:schedule",
                    link_text="Schedule",
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_snmp_sync:schedule_edit",
                            title="Edit schedule & seed IPs",
                            icon_class="mdi mdi-pencil",
                        ),
                    ),
                ),
            ),
        ),
        (
            "MAC Addresses",
            (
                PluginMenuItem(
                    link="plugins:netbox_snmp_sync:learned_mac_list",
                    link_text="Learned MACs",
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_snmp_sync:learned_mac_list",
                            title="View all learned MAC addresses",
                            icon_class="mdi mdi-ethernet",
                        ),
                    ),
                ),
                PluginMenuItem(
                    link="plugins:netbox_snmp_sync:oui_list",
                    link_text="OUI Databases",
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_snmp_sync:oui_list",
                            title="Manage OUI vendor lookup files",
                            icon_class="mdi mdi-database",
                        ),
                    ),
                ),
            ),
        ),
        (
            "Configuration",
            (
                PluginMenuItem(
                    link="plugins:netbox_snmp_sync:credential_list",
                    link_text="SNMP Credentials",
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_snmp_sync:credential_add",
                            title="Add credential",
                            icon_class="mdi mdi-plus-thick",
                            color=PluginMenuButton.GREEN,
                        ),
                    ),
                ),
            ),
        ),
    ),
    icon_class="mdi mdi-network-outline",
)
