#!/bin/bash

mv eval.log eval.log.old
while true; do
        ../../analysis/target/release/jmpscare -n 1000 -y -a ARM ../modem_raw.img --traces ./cov >> eval.log
        cd cov
	ls . | tail -n 1
	ls . | tail -n 1 >> eval.log
        rm $(ls . | tail -n 1) || exit 0
        cd ..
done
