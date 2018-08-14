#!/usr/bin/env bash

for t in $(ls $1/*.json)
do
    tail -1 $1/$t > tmp
    mv tmp $1/$t
done

rm tmp