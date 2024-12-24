from enum import Enum

# Nmap Options
NMAP_OPTIONS = {
    "host_discovery": "-sn",
    "speed_up": "-T4",
    "service_version": "-sV",
    "os_detection": "-O",
    "aggressive": "-A",
    "vuln_scan": "--script=vuln",
    "all_ports": "-p-",
    "save_result": "-oN"
}


class CommonPorts(Enum):
    """
    Enum to define common ports for services.
    """
    PORT_20_FTP_DATA = "20/tcp"
    PORT_21_FTP_CONTROL = "21/tcp"
    PORT_22_SSH = "22/tcp"
    PORT_23_TELNET = "23/tcp"
    PORT_25_SMTP = "25/tcp"
    PORT_53_DNS = "53/tcp"
    PORT_80_HTTP = "80/tcp"
    PORT_110_POP3 = "110/tcp"
    PORT_135_MS_RPC = "135/tcp"
    PORT_139_NETBIOS = "139/tcp"
    PORT_143_IMAP = "143/tcp"
    PORT_443_HTTPS = "443/tcp"
    PORT_445_SMB = "445/tcp"
    PORT_3306_MYSQL = "3306/tcp"
    PORT_3389_RDP = "3389/tcp"
    PORT_5432_POSTGRESQL = "5432/tcp"
    PORT_5900_VNC = "5900/tcp"
    PORT_8080_HTTP_ALT = "8080/tcp"


class NmapFeatures(Enum):
    """
    Enum to define Nmap script checks and features for specific ports.
    """
    # Port 20-21 FTP Features
    PORT_20_21_FTP_VULNERS = "| vulners"
    PORT_21_FTP_ANON = "| ftp-anon"

    # Port 22 SSH Features
    PORT_22_VULNERS = "| vulners"

    # Port 23 Telnet Features
    PORT_23_TELNET_VULN = "| telnet-vuln"

    # Port 80 HTTP Features
    PORT_80_HTTP_ENUM = "| http-enum"
    PORT_80_VULNERS = "| vulners"
    PORT_80_HTTP_SERVER_HEADER = "|_http-server-header"
    PORT_80_HTTP_CSRF = "|_http-csrf:"
    PORT_80_HTTP_DOMBASED_XSS = "|_http-dombased-xss"
    PORT_80_HTTP_STORED_XSS = "|_http-stored-xss"
    PORT_80_HTTP_TRACE = "|_http-trace"
    PORT_80_HTTP_SQL_INJECTION = "| http-sql-injection"
    PORT_80_SLOWLORIS_CHECK = "| http-slowloris-check"
    PORT_80_CSS_INJECTION = "| ssl-ccs-injection"

    # Port 110 POP3 Features
    PORT_110_POP3_VULN = "| pop3-capabilities"

    # Port 135 RPC Features
    PORT_135_MS_RPCS = "| msrpc-enum"

    # Port 139 and 445 SMB Features
    PORT_139_445_NETBIOS_SMB_VULN = "| smb-vuln-cve2009-3103"
    PORT_139_445_SMB_VULN_CVE2012_1182 = "| samba-vuln-cve-2012-1182"

    # Port 143 IMAP Features
    PORT_143_IMAP_CVE = "| imap-capabilities"

    # Port 443 SSL/TLS Features
    PORT_443_SSL_CCS_INJECTION = "| ssl-ccs-injection"
    PORT_443_VULNERS = "| vulners"
    PORT_443_SSL_DH_PARAMS = "| ssl-dh-params"
    PORT_443_SSL_POODLE = "| ssl-poodle"
    PORT_443_SSLV2_DROWN = "| sslv2-drown"
    PORT_443_HTTP_SERVER_HEADER = "|_http-server-header"

    # Port 3306 MySQL Features
    PORT_3306_MYSQL_ENUM = "| mysql-enum"

    # Port 3389 RDP Features
    PORT_3389_RDP_ENUM = "| rdp-enum"
    PORT_3389_RDP_VULNERS = "| vulners"

    # Port 5432 PostgreSQL Features
    PORT_5432_POSTGRES_ENUM = "| pgsql-databases"

    # Generic Features or Errors
    ERROR_CLAMAV_EXEC = "|_clamav-exec"


# Mapping CommonPorts to NmapFeatures
PORT_FEATURE_MAPPING = {
    # FTP Ports
    CommonPorts.PORT_20_FTP_DATA: [
        NmapFeatures.PORT_20_21_FTP_VULNERS,
    ],
    CommonPorts.PORT_21_FTP_CONTROL: [
        NmapFeatures.PORT_20_21_FTP_VULNERS,
        NmapFeatures.PORT_21_FTP_ANON,
    ],

    # SSH Port
    CommonPorts.PORT_22_SSH: [
        NmapFeatures.PORT_22_VULNERS,
    ],

    # Telnet Port
    CommonPorts.PORT_23_TELNET: [
        NmapFeatures.PORT_23_TELNET_VULN,
    ],

    # HTTP Ports
    CommonPorts.PORT_80_HTTP: [
        NmapFeatures.PORT_80_HTTP_ENUM,
        NmapFeatures.PORT_80_VULNERS,
        NmapFeatures.PORT_80_HTTP_SERVER_HEADER,
        NmapFeatures.PORT_80_HTTP_CSRF,
        NmapFeatures.PORT_80_HTTP_DOMBASED_XSS,
        NmapFeatures.PORT_80_HTTP_STORED_XSS,
        NmapFeatures.PORT_80_HTTP_TRACE,
        NmapFeatures.PORT_80_HTTP_SQL_INJECTION,
        NmapFeatures.PORT_80_SLOWLORIS_CHECK,
    ],

    # HTTPS Port
    CommonPorts.PORT_443_HTTPS: [
        NmapFeatures.PORT_443_SSL_CCS_INJECTION,
        NmapFeatures.PORT_443_VULNERS,
        NmapFeatures.PORT_443_SSL_POODLE,
        NmapFeatures.PORT_443_SSLV2_DROWN,
        NmapFeatures.PORT_443_HTTP_SERVER_HEADER,
    ],

    # SMB Ports
    CommonPorts.PORT_139_NETBIOS: [
        NmapFeatures.PORT_139_445_NETBIOS_SMB_VULN,
        NmapFeatures.PORT_139_445_SMB_VULN_CVE2012_1182,
    ],
    CommonPorts.PORT_445_SMB: [
        NmapFeatures.PORT_139_445_NETBIOS_SMB_VULN,
        NmapFeatures.PORT_139_445_SMB_VULN_CVE2012_1182,
    ],

    # MySQL Port
    CommonPorts.PORT_3306_MYSQL: [
        NmapFeatures.PORT_3306_MYSQL_ENUM,
    ],

    # RDP Port
    CommonPorts.PORT_3389_RDP: [
        NmapFeatures.PORT_3389_RDP_ENUM,
        NmapFeatures.PORT_3389_RDP_VULNERS,
    ],

    # PostgreSQL Port
    CommonPorts.PORT_5432_POSTGRESQL: [
        NmapFeatures.PORT_5432_POSTGRES_ENUM,
    ],

    # Alternate HTTP Port
    CommonPorts.PORT_8080_HTTP_ALT: [
        NmapFeatures.PORT_80_HTTP_ENUM,
        NmapFeatures.PORT_80_VULNERS,
        NmapFeatures.PORT_80_HTTP_SERVER_HEADER,
        NmapFeatures.PORT_80_HTTP_CSRF,
        NmapFeatures.PORT_80_HTTP_TRACE,
    ]
}
