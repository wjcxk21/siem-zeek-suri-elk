##! Local site policy. Customize as appropriate.
##!
##! This file will not be overwritten when upgrading or reinstalling!

# This script logs which scripts were loaded during each run.
@load misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
# 应用一般调优设置
@load tuning/defaults

# Estimate and log capture loss.
# 评估和记录抓包掉包情况
@load misc/capture-loss

# Enable logging of memory, packet and lag statistics.
# 启用内存、包量和时间间隔统计功能
@load misc/stats

# Load the scan detection script.
# 扫描检测功能
@load misc/scan

# Detect traceroute being run on the network. This could possibly cause
# performance trouble when there are a lot of traceroutes on your network.
# Enable cautiously.
# 检测网络中的traceroute。当网络中有太多traceroutes，可能造成性能问题。
# 谨慎启用
#@load misc/detect-traceroute

# Generate notices when vulnerable versions of software are discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more
# information.
# 提示出现有漏洞版本的软件。
# 参考software framework获取更多信息
@load frameworks/software/vulnerable

# Detect software changing (e.g. attacker installing hacked SSHD).
# 检测软件更改（如：攻击者安装hacked SSHD）
@load frameworks/software/version-changes

# This adds signatures to detect cleartext forward and reverse windows shells.
# 利用特征检测明文的windows shells
@load-sigs frameworks/signatures/detect-windows-shells

# Load all of the scripts that detect software in various protocols.
# 检测不同协议中传输的软件
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
# The detect-webapps script could possibly cause performance trouble when
# running on live traffic.  Enable it cautiously.
# 实时流量检测时要谨慎启用
@load protocols/http/detect-webapps

# This script detects DNS results pointing toward your Site::local_nets
# where the name is not part of your local DNS zone and is being hosted
# externally.  Requires that the Site::local_zones variable is defined.
# @load protocols/dns/detect-external-names

# Script to detect various activity in FTP sessions.
# 检测FTP会话中的各种行为
@load protocols/ftp/detect

# Scripts that do asset tracking.
# 资产跟踪
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs

# This script enables SSL/TLS certificate validation.
# SSL/TLS证书确认
@load protocols/ssl/validate-certs

# This script prevents the logging of SSL CA certificates in x509.log
# @load protocols/ssl/log-hostcerts-only

# Uncomment the following line to check each SSL certificate hash against the ICSI
# certificate notary service; see http://notary.icsi.berkeley.edu .
# @load protocols/ssl/notary

# If you have GeoIP support built in, do some geographic detections and
# logging for SSH traffic.
# @load protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
@load protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
@load protocols/ssh/interesting-hostnames

# Detect SQL injection attacks.
@load protocols/http/detect-sqli

#### Network File Handling ####

# Enable MD5 and SHA1 hashing for all files.
@load frameworks/files/hash-all-files

# Detect SHA1 sums in Team Cymru's Malware Hash Registry.
# @load frameworks/files/detect-MHR

# Extend email alerting to include hostnames
@load policy/frameworks/notice/extend-email/hostnames

# Uncomment the following line to enable detection of the heartbleed attack. Enabling
# this might impact performance a bit.
# @load policy/protocols/ssl/heartbleed

# Uncomment the following line to enable logging of connection VLANs. Enabling
# this adds two VLAN fields to the conn.log file.
# @load policy/protocols/conn/vlan-logging

# Uncomment the following line to enable logging of link-layer addresses. Enabling
# this adds the link-layer address for each connection endpoint to the conn.log file.
# @load policy/protocols/conn/mac-logging
