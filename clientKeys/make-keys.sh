#!/bin/bash

rm *.{private,key}



for i in {0..255}
do
dnssec-keygen -a ECDSA384 -b 2048 -n ZONE $i.orionet.re
dnssec-dsfromkey "K$i.orionet.re.*.key" > "dsset/records.dsset"
done
