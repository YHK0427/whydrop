"""Cause labels and next steps (spec §6.4). Every label says "likely": whydrop infers, it doesn't know."""

CAUSES = {
    "R1a": ("Wi-Fi problem (likely)",
            "If the signal was weak, move the AP or change channel. If the AP vanished, check its power or reboot it"),
    "R1a_roam": ("Wi-Fi roaming with loss (likely)",
                 "Roaming between APs dropped packets: check that the APs share settings, or pin the device to one AP"),
    "R1c": ("Wired link problem (likely)", "Check the cable and the switch port"),
    "R1d": ("Host network configuration lost (likely)",
            "Restart the host's network service (e.g. NetworkManager); if it repeats, check DHCP leases"),
    "R1b": ("Router problem (likely)", "Reboot the router; if it repeats, attach the records"),
    "R4": ("Public IP change (likely)",
           "The ISP reassigned your IP. If it happens often, contact them with the records"),
    "R5": ("NAT/firewall state lost (likely)", "Set keepalive to the value nat-test recommends, or less"),
    "R5_expiry": ("NAT/firewall state expired (likely)",
                  "The idle interval is longer than the measured NAT timeout: set keepalive below it"),
    "R5_loss": ("NAT/firewall state lost before its timeout (likely)",
                "The NAT forgot a connection sooner than nat-test measured: check for router restarts"),
    "R2_unobservable": ("Router or line, can't separate (likely)",
                        "The router doesn't answer probes, so whydrop can't tell it from the line"),
    "R1b_unobservable": ("Router or line, can't separate (likely)",
                         "The link state is unknown, so whydrop can't tell the router from the line"),
    "R5_reset": ("NAT state reset (likely)", "Check for router or CGNAT restarts"),
    "R3": ("DNS failure (likely)", "Switch your device or router to a public DNS"),
    "R2": ("Line drop in the ISP segment (likely)", "Save the evidence with export and contact your ISP"),
    "R6": ("Lossy line (likely)", "Save the evidence and contact your ISP"),
    "R6_path": ("Lossy path to the reflector (likely)", "Save the evidence; the loss is on the way to the reflector"),
    "R7": ("High latency from queueing (likely)", "Enable SQM (cake/fq_codel) on the router, or limit uploads"),
    "unknown": ("No known pattern matched (likely something new)",
                "Please file a \"wrong diagnosis\" issue with the records attached"),
}

R3_LABELS = {
    "router": "Router DNS failure (likely)",
    "router_upstream": "Router DNS or its upstream failure (likely)",
    "isp": "ISP DNS failure (likely)",
    "isp_outage": "ISP DNS outage (likely)",
    "public": "Public resolvers blocked or filtered on this network (likely)",
    "wide": "DNS-wide failure (likely)",
}

ROUTER_RESTART = "router restart (likely)"
IN_HOME_QUEUEING = "In-home queueing (likely)"
IN_HOME_STEP = "The delay starts before the router: check the Wi-Fi signal and heavy traffic from other devices at home"
QUEUEING_TIMEOUTS = "Queueing caused the timeouts (likely)"
