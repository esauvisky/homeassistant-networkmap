"""Constants for the Network Map integration."""

DOMAIN = "networkmap"

PLATFORMS = ["device_tracker"]

DEFAULT_PORT = 8081
DEFAULT_SCAN_INTERVAL = 30
DEVICE_SCAN_INTERVAL = 30
MIN_SCAN_INTERVAL = 10

CONF_SCAN_INTERVAL = "scan_interval"
CONF_API_KEY = "api_key"

# Scan type configuration options
CONF_ENABLE_NET_PROBE = "enable_net_probe"
CONF_ENABLE_NET_SNIFF = "enable_net_sniff"
CONF_ENABLE_ARP_SPOOF = "enable_arp_spoof"
CONF_ENABLE_TICKER = "enable_ticker"
CONF_ENABLE_NET_RECON = "enable_net_recon"
CONF_ENABLE_ZEROGOD = "enable_zerogod"

# Default scan options
DEFAULT_ENABLE_NET_PROBE = True
DEFAULT_ENABLE_NET_SNIFF = True
DEFAULT_ENABLE_ARP_SPOOF = False
DEFAULT_ENABLE_TICKER = True
DEFAULT_ENABLE_NET_RECON = True
DEFAULT_ENABLE_ZEROGOD = True

# Bettercap API endpoint
BETTERCAP_API_URL = "http://{host}:{port}/api"

# Bettercap commands
BETTERCAP_NET_PROBE_ON = "net.probe on"
BETTERCAP_NET_PROBE_OFF = "net.probe off"
BETTERCAP_NET_SNIFF_ON = "net.sniff on"
BETTERCAP_NET_SNIFF_OFF = "net.sniff off"
BETTERCAP_ARP_SPOOF_ON = "arp.spoof on"
BETTERCAP_ARP_SPOOF_OFF = "arp.spoof off"
BETTERCAP_TICKER_ON = "ticker on"
BETTERCAP_TICKER_OFF = "ticker off"
BETTERCAP_NET_RECON_ON = "net.recon on"
BETTERCAP_NET_RECON_OFF = "net.recon off"
BETTERCAP_NET_SHOW_META_ON = "set net.show.meta true"
BETTERCAP_ZEROGOD_DISCOVERY_ON = "zerogod.discovery on"
BETTERCAP_ZEROGOD_DISCOVERY_OFF = "zerogod.discovery off"

# Targeted verification commands
BETTERCAP_NET_PROBE_TARGET = "net.probe {target}"  # For targeted probing
BETTERCAP_ARP_PROBE_TARGET = "arp.probe {target}"  # For ARP probing
BETTERCAP_PING_TARGET = "net.ping {target}"        # For ICMP ping

# Verification settings
VERIFICATION_ATTEMPTS = 2  # Number of verification attempts before marking offline
VERIFICATION_DELAY = 5     # Delay between verification attempts (seconds)

# Device naming options - removed explicit options, now always smart update
