#!/bin/bash
hex_key=$(head -c 32 /dev/urandom | xxd -p)
base64_key=$(head -c 32 /dev/urandom | base64)
echo -n "32-byte Random Key (Hex): "
echo "$hex_key"
echo -n "32-byte Random Key (Base64): "
echo "$base64_key"
