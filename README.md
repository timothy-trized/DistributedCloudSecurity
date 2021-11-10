# TRIZEd - Distributed Cloud Security

**Protect your private cloud from bad traffic**

`trized_dcs.inc.php` - Main DCS connection library

`example_security.php` - Place this code snippet on top of your website, landing page or application to secure it


**Integrating DCS into Iptables firewall using Ipset and CRON:**

`example_iptables.php` - Use this code with CRON to automatically integrate DCS with Ipset and the Iptables firewall on Linux

`*/30 * * * * php -q /root/dcs/example_iptables.php >/dev/null 2>&1`


