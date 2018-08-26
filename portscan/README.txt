ðTCP/UDP port scan.
Program supports protocol recognition [NTP/DNS/SMTP/POP3/IMAP/HTTP].
(But there may be failures due to a tcp connection failure).

For help:
>portscan.py -h [--help]

Launch examples:
>python portscan.py google.com -t -p 80 90
TCP 80 [HTTP]
>python portscan.py smtp.gmx.com -t -p 20 30
TCP 25 [SMTP]
>python portscan.py imap.mail.ru -t -p 140 150
TCP 143 [IMAP]
>python portscan.py pop.mail.ru -t -p 110 120
TCP 110 [POP3]
>python portscan.py 77.88.8.1 -u -p 50 60
UDP 53 DNS
>python portscan.py pool.ntp.org -u -p 120 130
UDP 123 NTP
