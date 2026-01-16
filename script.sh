#!/bin/bash

# Step 1: Get a bearer token
TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/ubuntu:pull" | jq -r .token)

# Step 2: Get the image manifest list
curl -s -H "Authorization: Bearer $TOKEN" \
     -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
     https://registry-1.docker.io/v2/library/ubuntu/manifests/latest \
     -o manifest-list.json

# Step 3a: Find the digest for the target platform (linux/amd64)
IMAGE_MANIFEST_DIGEST=$(jq -r '.manifests[] | select(.platform.architecture == "amd64" and .platform.os == "linux") | .digest' manifest-list.json)

# Step 3b: Get the platform-specific image manifest
curl -s -H "Authorization: Bearer $TOKEN" \
     -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
     https://registry-1.docker.io/v2/library/ubuntu/manifests/$IMAGE_MANIFEST_DIGEST \
     -o manifest.json

# Step 4 & 5: Loop through all layers
LAYER_DIGESTS=$(jq -r '.layers[].digest' manifest.json)

for DIGEST in $LAYER_DIGESTS; do
    echo "Checking existence of layer $DIGEST..."
    curl -s -I -H "Authorization: Bearer $TOKEN" \
         https://registry-1.docker.io/v2/library/ubuntu/blobs/$DIGEST

    echo "Downloading layer $DIGEST..."
    curl -L -H "Authorization: Bearer $TOKEN" \
         -o "${DIGEST//:/_}.tar" \
         https://registry-1.docker.io/v2/library/ubuntu/blobs/$DIGEST
done

echo "All layers downloaded."

