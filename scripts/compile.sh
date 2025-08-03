#!/bin/bash  

MAIN_DIR="wg-mgr-rs"
IFS='/' #setting space as delimiter  
read -ra ADDR <<<"$PWD" #reading str as an array as tokens separated by IFS  

master_dir=""
for i in "${ADDR[@]}"; #accessing each element of array  
do  
    if [[ "$i" == "" ]]; then 
        continue
    fi
    master_dir="$master_dir/$i"
    if [[ "$i" == "wg-manager" ]]; then 
        break
    fi

done  

IFS=' ' #setting space as delimiter  

echo "move to root directory $master_dir"
cd "$master_dir/$MAIN_DIR"

cargo build

