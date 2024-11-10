#!/usr/bin/env bash

set -eux

readonly BASE_DIR="$(dirname "${PWD}")"
readonly REFERENCE_DIR="${BASE_DIR}/references"

gather_repositories() {
    local base_repo_dir="${REFERENCE_DIR}/projects"

    local -A repositories=(
    [https://github.com/eclipse-paho/paho.mqtt.python]=eclipse-paho_paho.mqtt.python
    [https://github.com/NotJustAToy/aio-mqtt]=NotJustAToy_aio-mqtt
    [https://github.com/empicano/aiomqtt]=empicano_aiomqtt
    [https://github.com/mossblaser/aiomqtt]=mossblaser_aiomqtt
    [https://github.com/njouanin/hbmqtt]=njouanin_hbmqtt
    [https://github.com/wialon/gmqtt]=wialon_gmqtt
    )

    mkdir -p "${base_repo_dir}"

    for repo_url in "${!repositories[@]}"; do
    target_dir="${repositories[$repo_url]}"
    full_path="${base_repo_dir}/${target_dir}"

    if ! [ -d "${full_path}" ];then
      git clone \
        "${repo_url}"  \
        "${full_path}"
    fi
    done
}

gather_docs() {
    local base_docs_dir="${REFERENCE_DIR}/docs"
    local docs_urls=(
        "https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.pdf"
        "https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html"
        "http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.pdf"
        "http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html"
        "https://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html"
    )

    mkdir -p "${base_docs_dir}"
    for url in "${docs_urls[@]}"; do
        # Extract the file name from the URL
        local file_name
        file_name="$(basename "$url")"
        local full_path="${base_docs_dir}/${file_name}"

        curl \
            --location "${url}" \
            --output "${full_path}"
    done
}


main() {
    if ! [ -d "${REFERENCE_DIR}" ];then
      mkdir -p "${REFERENCE_DIR}"
    fi
    gather_repositories
    gather_docs
}
main