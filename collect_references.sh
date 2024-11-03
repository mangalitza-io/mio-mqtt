#!/usr/bin/env bash

set -eux

# https://github.com/eclipse-paho/paho.mqtt.python
# https://github.com/NotJustAToy/aio-mqtt
# https://github.com/empicano/aiomqtt
# https://github.com/mossblaser/aiomqtt
# https://github.com/njouanin/hbmqtt
# https://github.com/wialon/gmqtt

readonly DEST_DIR="${PWD}/referenceDir"

declare -A repositories=(
    [https://github.com/eclipse-paho/paho.mqtt.python]=eclipse-paho_paho.mqtt.python
    [https://github.com/NotJustAToy/aio-mqtt]=NotJustAToy_aio-mqtt
    [https://github.com/empicano/aiomqtt]=empicano_aiomqtt
    [https://github.com/mossblaser/aiomqtt]=mossblaser_aiomqtt
    [https://github.com/njouanin/hbmqtt]=njouanin_hbmqtt
    [https://github.com/wialon/gmqtt]=wialon_gmqtt
)

mkdir -p "${DEST_DIR}"
for repo_url in "${!repositories[@]}"; do
    target_dir="${repositories[$repo_url]}"
    full_path="${DEST_DIR}/${target_dir}"

    if ! [ -d "${full_path}" ];then
      git clone \
        "${repo_url}"  \
        "${full_path}"
    fi
done