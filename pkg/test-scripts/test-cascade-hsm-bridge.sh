#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    echo -e "\nCASCADE-HSM-BRIDGE VERSION:"
    cascade-hsm-bridge --version

    echo -e "\nCASCADE-HSM-BRIDGE CONF:"
    cat /etc/cascade-hsm-bridge/config.toml

    echo -e "\nCASCADE-HSM-BRIDGE SERVICE STATUS:"
    systemctl status cascade-hsm-bridge || true

    echo -e "\nCASCADE-HSM-BRIDGE MAN PAGE (first 20 lines only):"
    man -P cat cascade-hsm-bridge | head -n 20 || true
    ;;

  post-upgrade)
    echo -e "\nCASCADE-HSM-BRIDGE VERSION:"
    cascade-hsm-bridge --version
    
    echo -e "\nCASCADE-HSM-BRIDGE CONF:"
    cat /etc/cascade-hsm-bridge/config.toml
    
    echo -e "\nCASCADE-HSM-BRIDGE SERVICE STATUS:"
    systemctl status cascade-hsm-bridge || true
    
    echo -e "\nCASCADE-HSM-BRIDGE MAN PAGE:"
    man -P cat cascade-hsm-bridge
    ;;
esac
