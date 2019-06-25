#!/bin/bash
#Description:

#Author: WuJiayan Email:wjcxkfifa@gmail.com
#Version:1.0
#CreateTime:2019-04-22 11:29:33

FROM docker.elastic.co/logstash/logstash:6.7.2
MAINTAINER Wjj <wjcxkfifa@gmail.com>

# 拷贝filter-geoip
COPY --chown=1000:1000 logstash-filter-geoip-6.0.0-java.gem /logstash-filter-geoip-6.0.0-java.gem
#COPY --chown=1000:1000 GeoIP2-City.mmdb /data/GeoIP2-City.mmdb
#COPY --chown=1000:1000 testgeoip.conf /testgeoip.conf

# 安装filter-geoip
RUN echo "===> Installing..." && \
	cd /usr/share/logstash && \
 	if ./bin/logstash-plugin list logstash-filter-geoip; then ./bin/logstash-plugin remove logstash-filter-geoip; fi && \
        ./bin/logstash-plugin install --no-verify --local /logstash-filter-geoip-6.0.0-java.gem 
USER root
RUN echo "===> Cleaning..." && \
	rm -f /logstash-filter-geoip-6.0.0-java.gem
USER 1000
