#!/bin/bash

mv eval.log eval.log.old
while true; do
        cd cov
        rm $(ls . | head -n 1)
        cd ..
        ../analysis/target/release/jmpscare -n 1000 -y -a ARM ./modem_raw.img --traces cov >> eval.log
done
