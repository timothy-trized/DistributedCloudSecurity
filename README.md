# TRIZEd - Distributed Cloud Security

**Protecting your private cloud from unwanted traffic (PHP example)**

Distributed Cloud Security can easily be implemented into your website, landing pages and other applications. Because of the REST API endpoint you could use any programming language to secure your private cloud infrastructure. The IP address of each visitor will be checked rapidly with multiple intelligence providers in order to check if the IP has been marked as Abuse, for scams or is a dangerous proxy like the TOR network.

Using this solution any visitor IP that has been marked as dangerous will be blocked with a **403 Forbidden** header and the connection will be terminated. With this in place you can make sure that only legit traffic is reaching your online content and bad guys are blocked minimizing the attack-surface and protecting your clients and servers automatically without human intervention.


`trized_dcs.inc.php` - Main DCS connection library

`example_security.php` - Place this code snippet on top of your website, landing page or application to secure it


**Integrating DCS into Iptables firewall using Ipset and CRON:**

`example_iptables.php` - Use this code with CRON to automatically integrate DCS with Ipset and the Iptables firewall on Linux

`*/30 * * * * php -q /root/dcs/example_iptables.php >/dev/null 2>&1`


