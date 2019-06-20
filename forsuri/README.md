# forsuri
包含suricata的docker

## 目录分布
工作目录为：/pcap
配置目录为：/etc/suricata
规则目录为：/etc/suricata/rules
    /etc/suricata # ls -l
    total 100
    -rw-r--r--    1 root     root           172 Jun 20 03:12 capture-filter.bpf
    -rw-r--r--    1 root     root          4167 Jun 20 03:12 classification.config
    -rw-r--r--    1 root     root             0 Jun 20 03:12 null.bpf
    -rw-r--r--    1 root     root          1375 Jun 20 03:12 reference.config
    drwxr-xr-x    2 root     root          4096 Jun 20 03:12 rules
    -rw-r--r--    1 root     root         74608 Jun 20 03:12 suricata.yaml
    -rw-r--r--    1 root     root          1644 Jun 20 03:12 threshold.config
默认的log目录为：/var/log/suricata

## 使用说明
处理本地离线pcap文件
    docker run -d -v "`pwd`:/pcap" -v "`pwd`/logs:/var/log/suricata" suricata:4.1.4 /usr/bin/suricata -c /etc/suricata/suricata.yaml -r yourfile.pcap

