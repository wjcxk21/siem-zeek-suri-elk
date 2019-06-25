FROM docker.elastic.co/elasticsearch/elasticsearch:6.7.2 as builder
LABEL maintainer "wjcxkfifa2@gmail.com"

ENV ES_VERSION "6.7.2"

COPY LicenseVerifier.java /tmp/
COPY XPackBuild.java /tmp/

RUN echo "===> Compiling the cracked x-pack-core" \
        && cd /tmp/ \
        && ${JAVA_HOME}/bin/javac -cp \
"/usr/share/elasticsearch/lib/elasticsearch-$ES_VERSION.jar:\
/usr/share/elasticsearch/lib/lucene-core-7.7.0.jar:\
/usr/share/elasticsearch/modules/x-pack-core/x-pack-core-$ES_VERSION.jar" \
        LicenseVerifier.java \
        && ${JAVA_HOME}/bin/javac -cp \
"/usr/share/elasticsearch/lib/elasticsearch-${ES_VERSION}.jar:\
/usr/share/elasticsearch/lib/lucene-core-7.7.0.jar:\
/usr/share/elasticsearch/modules/x-pack-core/x-pack-core-$ES_VERSION.jar:\
/usr/share/elasticsearch/lib/elasticsearch-core-$ES_VERSION.jar" \
        XPackBuild.java \
        && mkdir jar-unpacked \
        && cd jar-unpacked \
        && cp -a /usr/share/elasticsearch/modules/x-pack-core/x-pack-core-$ES_VERSION.jar . \
        && ${JAVA_HOME}/bin/jar -xf x-pack-core-$ES_VERSION.jar \
        && cp -af ../LicenseVerifier.class org/elasticsearch/license/ \
        && cp -af ../XPackBuild.class org/elasticsearch/xpack/core/ \
        && rm -rf x-pack-core-$ES_VERSION.jar \
        ##删除正常的jar \
        && ${JAVA_HOME}/bin/jar -cvf x-pack-core-$ES_VERSION.jar * 
        ##生成破解版的jar，大小比原始的jar略大
RUN echo "===> Size of the cracked x-pack-core" \
    && ls -lh /tmp/jar-unpacked/x-pack-core-$ES_VERSION.jar

###########################################################################
FROM docker.elastic.co/elasticsearch/elasticsearch:6.7.2
LABEL maintainer "wjcxkfifa2@gmail.com"

ENV ES_VERSION "6.7.2"

COPY --from=builder --chown=1000:root \
/tmp/jar-unpacked/x-pack-core-$ES_VERSION.jar \
/usr/share/elasticsearch/modules/x-pack-core/x-pack-core-$ES_VERSION.jar 

