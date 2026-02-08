#!/bin/bash
GHIDRA=/xxx/ghidra_12.1_PUBLIC/support/analyzeHeadless
PROJ=/xxx/ghidra
SCRIPTS=/xxx/ghidra_scripts
BINS=/xxx/data
OUT=/xxx/out

BINARIES="bzip2 h264ref hmmer  lighttpd  memcached milc omnetpp sjeng thttpd"

for bin in $BINARIES; do
    echo "===== START $bin @ $(date) =====" | tee -a /tmp/bindsa_run2.log
    $GHIDRA $PROJ spec \
        -import $BINS/$bin \
        -overwrite \
        -scriptPath $SCRIPTS \
        -preScript SetAutoAnalysisOptions.java \
        -postScript IndirectCallTargetResolving.java \
        >> /tmp/bindsa_run2.log 2>&1
    echo "===== END $bin @ $(date) =====" | tee -a /tmp/bindsa_run2.log
    # save results for this binary
    cp $OUT/solved_copy.txt $OUT/${bin}_solved.txt
    cp $OUT/targets.txt $OUT/${bin}_targets.txt
done

echo "ALL DONE @ $(date)" | tee -a /tmp/bindsa_run2.log
