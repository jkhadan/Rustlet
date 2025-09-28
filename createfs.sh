#!/bin/bash
CONTAINER_ROOT="/home/jkhadan/projects/Rustlet/container"

# Create directory structure
mkdir -p $CONTAINER_ROOT/{bin,lib,lib64,proc,sys,dev,etc,tmp,usr/bin}

# Copy bash and its dependencies
cp /bin/bash $CONTAINER_ROOT/bin/
cp /bin/sh $CONTAINER_ROOT/bin/
cp /bin/ls $CONTAINER_ROOT/bin/
cp /bin/cat $CONTAINER_ROOT/bin/
cp /bin/echo $CONTAINER_ROOT/bin/

# Copy shared libraries (use ldd to find dependencies)
# This copies all libraries bash needs
for lib in $(ldd /bin/bash | grep -o '/lib.*\.[0-9]' | sort -u); do
    cp --parents "$lib" "$CONTAINER_ROOT"
done

# Create basic /etc files
echo "root:x:0:0:root:/root:/bin/bash" > $CONTAINER_ROOT/etc/passwd
echo "root:x:0:" > $CONTAINER_ROOT/etc/group