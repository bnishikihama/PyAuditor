# Interface for Sniffing traffic
interface = "Ethernet"

# IP block threshold - number of infractions a single IP is allowed before iptable block
ban_threshold = 5

# Ports that will be let through (ignored by program)
whitelist_ports = [443]

# IP addresses that are protected and will not trigger any rules
whitelist_ip = ["192.168.1.105"]

# Ports that will trigger rules
target_ports = [21, 22, 23, 25, 80, 110, 143, 445, 1433, 1521, 3306, 3389, 5432, 6379, 7001, 8080, 9200, 27017]

# Number of duplicate sequence numbers allowed from same IP
num_seq_dup = 5

# Protocols to Detect
# Note: HTTP will not count towards an infraction
target_protocols = {
    "ssh": True,
    "http": True,
    "ftp": True,
    "telnet": True
}

# Keywords to detect as secret messages in payload
keywords = ["secret", "test"]
