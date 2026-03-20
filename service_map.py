SERVICE_MAP = {
    20:    "FTP Data",
    21:    "FTP Control",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    27017: "MongoDB",
}

PORT_PROBES = {
    80:   b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    443:  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    21:   b"",
    22:   b"",
    25:   b"",
}