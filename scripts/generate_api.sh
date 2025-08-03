#!/bin/bash  

API_DIR="wg-mgr-api"
API_VERSION="0.1.0"
  
IFS='/' #setting space as delimiter  
read -ra ADDR <<<"$PWD" #reading str as an array as tokens separated by IFS  

master_dir=""
for i in "${ADDR[@]}"; #accessing each element of array  
do  
    if [[ "$i" == "" ]]; then 
        continue
    fi
    if [[ "$i" == "wg-mgr-rs" ]]; then
        break
    fi
    if [[ "$i" == "wg-client" ]]; then
        break
    fi
    master_dir="$master_dir/$i"

done  

echo "move to root directory $master_dir"
cd "$master_dir"

sudo rm -rf "$API_DIR"
docker run --rm -v "${PWD}:/local" \
        cylonix/openapi-generator-cli:v7.8.5 \
        generate -g rust-server \
        -i /local/openapi/wg/wg.yaml \
        -o /local/$API_DIR \
        --additional-properties=packageName=wg-api,packageVersion=${API_VERSION}

# Change mode, need the priveldge 
sudo chown -R $USER:$USER $API_DIR

# fmt the code 
cd "$master_dir/$API_DIR"
cargo fmt

IFS=' ' # reset the spliter 
