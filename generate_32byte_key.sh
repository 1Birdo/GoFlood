#!/bin/bash

# Generate 32-byte random key in HEX
hex_key=$(head -c 32 /dev/urandom | xxd -p)

# Generate 32-byte random key in Base64
base64_key=$(head -c 32 /dev/urandom | base64)

echo -n "🔐 32-byte Random Key (Hex): "
echo "$hex_key"

echo -n "🔐 32-byte Random Key (Base64): "
echo "$base64_key"
