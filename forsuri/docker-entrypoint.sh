#! /bin/bash

if [[ -z $1 ]] || [[ ${1:0:1} == '-' ]] ; then
    exec "/usr/bin/suricata" "$@"
else
    exec "$@"
fi
