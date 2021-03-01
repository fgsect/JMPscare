# How to Eval

For our simple evaluation, we run jmpscare on all files, then remove x traces each round, and rerun.
To collect traces, we used the collector from [the collector](../collection) on the [BaseSAFE ERRC harness](https://github.com/fgsect/BaseSAFE/tree/master/examples/errc).

A range of cov traces from fuzzing ERRC are [included](./cov.zip) in this folder, to test the analysis, unpack them, and download BaseSAFE's mtk [modem_raw.img](https://github.com/fgsect/BaseSAFE/raw/master/examples/modem_raw.img).