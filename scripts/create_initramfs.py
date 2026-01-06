#!/usr/bin/env python3
import os
import gzip
from pathlib import Path

inode_counter = 1

def get_inode():
    global inode_counter
    inode_counter += 1
    return inode_counter

def cpio_header(ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor, rdevmajor, rdevminor, namesize, check):
    return (f"070701"
            f"{ino:08X}"
            f"{mode:08X}"
            f"{uid:08X}"
            f"{gid:08X}"
            f"{nlink:08X}"
            f"{mtime:08X}"
            f"{filesize:08X}"
            f"{devmajor:08X}"
            f"{devminor:08X}"
            f"{rdevmajor:08X}"
            f"{rdevminor:08X}"
            f"{namesize:08X}"
            f"{check:08X}").encode('ascii')

def align4(n):
    return (n + 3) & ~3

def add_entry(entries, name, mode, content=b'', rdevmajor=0, rdevminor=0, nlink=1):
    name_bytes = name.encode('utf-8') + b'\x00'
    namesize = len(name_bytes)
    filesize = len(content)
    
    header = cpio_header(
        get_inode(), mode, 0, 0, nlink, 0, filesize,
        0, 0, rdevmajor, rdevminor, namesize, 0
    )
    
    header_name = header + name_bytes
    pad1 = align4(len(header_name)) - len(header_name)
    header_name_padded = header_name + b'\x00' * pad1
    
    pad2 = align4(filesize) - filesize if filesize > 0 else 0
    content_padded = content + b'\x00' * pad2
    
    entries.append(header_name_padded + content_padded)

def add_file(entries, name, source_path, mode=0o100755):
    with open(source_path, 'rb') as f:
        content = f.read()
    add_entry(entries, name, mode, content)

def add_symlink(entries, name, target):
    add_entry(entries, name, 0o120777, target.encode('utf-8'))

def add_dir(entries, name, mode=0o040755):
    add_entry(entries, name, mode, nlink=2)

def add_chardev(entries, name, mode, major, minor):
    add_entry(entries, name, 0o020000 | mode, rdevmajor=major, rdevminor=minor)

entries = []
base = Path('/tmp/initramfs-virt')

add_entry(entries, '.', 0o040755, nlink=10)

# Device nodes
add_dir(entries, 'dev', 0o040755)
add_chardev(entries, 'dev/console', 0o622, 5, 1)
add_chardev(entries, 'dev/null', 0o666, 1, 3)
add_chardev(entries, 'dev/ttyAMA0', 0o666, 204, 64)
add_chardev(entries, 'dev/kmsg', 0o644, 1, 11)  # /dev/kmsg for printk output

# Directories
for d in ['proc', 'sys', 'tmp', 'etc', 'sbin', 'bin', 'lib', 'lib/modules', 'lib/modules/6.6.110-0-virt', 'lib/modules/6.6.110-0-virt/kernel']:
    add_dir(entries, d)

# Init script that uses /dev/kmsg for output
init_content = b'''#!/bin/sh
# Simple init that uses printk for output
export PATH=/bin:/sbin

# Helper to write to kernel log
log() {
    echo "<6>init: $1" > /dev/kmsg 2>/dev/null || true
}

# Helper to run insmod with error capture
try_insmod() {
    MODULE="$1"
    NAME="$2"
    if [ ! -f "$MODULE" ]; then
        log "$NAME: FILE NOT FOUND"
        return 1
    fi
    ERR=$(/bin/busybox insmod "$MODULE" 2>&1)
    RET=$?
    if [ $RET -eq 0 ]; then
        log "$NAME: OK"
    else
        log "$NAME: FAIL($RET) $ERR"
    fi
    return $RET
}

log "Starting init..."

/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys

log "Filesystems mounted"

# List what modules are available
MODDIR="/lib/modules/6.6.110-0-virt/kernel"
log "Listing modules in $MODDIR:"
log "Contents of /lib:"
/bin/busybox ls -la /lib 2>&1 | while read line; do log "  $line"; done
log "Contents of /lib/modules:"
/bin/busybox ls -la /lib/modules 2>&1 | while read line; do log "  $line"; done
log "Contents of /lib/modules/6.6.110-0-virt:"
/bin/busybox ls -la /lib/modules/6.6.110-0-virt 2>&1 | while read line; do log "  $line"; done
log "Contents of $MODDIR:"
/bin/busybox ls -la $MODDIR 2>&1 | while read line; do log "  $line"; done
log "Contents of $MODDIR/drivers/virtio:"
/bin/busybox ls -la $MODDIR/drivers/virtio 2>&1 | while read line; do log "  $line"; done
for f in $MODDIR/drivers/virtio/*.ko $MODDIR/net/vmw_vsock/*.ko; do
    if [ -f "$f" ]; then
        SIZE=$(/bin/busybox ls -l "$f" | /bin/busybox awk '{print $5}')
        log "  $f ($SIZE bytes)"
    fi
done

# Check kernel config for module support
if [ -f /proc/config.gz ]; then
    log "Kernel config available"
else
    log "No /proc/config.gz"
fi

# Show loaded modules
log "Currently loaded modules:"
/bin/busybox cat /proc/modules > /tmp/mods.txt 2>&1
if [ -s /tmp/mods.txt ]; then
    while read line; do
        log "  $line"
    done < /tmp/mods.txt
else
    log "  (none)"
fi

# Load vsock modules
log "Loading modules..."
try_insmod "$MODDIR/drivers/virtio/virtio_mmio.ko" "virtio_mmio"
try_insmod "$MODDIR/../../../net/vmw_vsock/vsock.ko" "vsock" || \
try_insmod "$MODDIR/net/vmw_vsock/vsock.ko" "vsock"
try_insmod "$MODDIR/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko" "vsock_common"
try_insmod "$MODDIR/net/vmw_vsock/vmw_vsock_virtio_transport.ko" "vsock_virtio"

# Check kernel messages for errors
log "Kernel messages after module load:"
/bin/busybox dmesg | /bin/busybox tail -10 | while read line; do
    log "  $line"
done

/bin/busybox sleep 1
if [ -e /dev/vsock ]; then
    log "/dev/vsock available!"
else
    log "/dev/vsock NOT available"
    # List vsock-related entries in /dev
    log "Checking /dev for vsock:"
    /bin/busybox ls -la /dev/ 2>&1 | /bin/busybox grep -i sock | while read line; do
        log "  $line"
    done
fi

# Configure network
/bin/busybox ip link set lo up
/bin/busybox ip addr add 127.0.0.1/8 dev lo

# Start proxy
if [ -x /bin/outbound-proxy ]; then
    log "Starting proxy..."
    # Run proxy in foreground first to see output, capture exit code
    /bin/outbound-proxy > /tmp/proxy.out 2>&1 &
    PROXY_PID=$!
    /bin/busybox sleep 2

    # Check if proxy is running
    if [ -d "/proc/$PROXY_PID" ]; then
        log "Proxy running as PID $PROXY_PID"
    else
        log "Proxy exited immediately!"
        log "Proxy output:"
        /bin/busybox cat /tmp/proxy.out 2>&1 | while read line; do log "  $line"; done
    fi

    # Check for open sockets
    log "Checking network:"
    /bin/busybox netstat -tlnp 2>&1 | while read line; do log "  $line"; done

    log "Running socks-test..."
    RESULT=$(/bin/socks-test 127.0.0.1:1080 example.com 80 2>&1)
    log "socks-test result: $? output: $RESULT"

    # Show proxy output
    log "Proxy output (last 10 lines):"
    /bin/busybox ps aux 2>&1 | while read line; do log "  $line"; done
fi

log "Init complete, starting shell loop"

# Run shell in a loop (it will exit if no tty, we restart it)
while true; do
    /bin/busybox sh 2>/dev/null
    /bin/busybox sleep 1
done
'''
add_entry(entries, 'init', 0o100755, init_content)

# Add binaries
for b in ['busybox', 'outbound-proxy', 'socks-test']:
    p = base / 'bin' / b
    if p.exists():
        add_file(entries, f'bin/{b}', p)

# Busybox symlinks
for cmd in ['sh', 'mount', 'insmod', 'ls', 'cat', 'echo', 'sleep', 'uname', 'grep', 'mknod', 'ip', 'hostname', 'setsid', 'head', 'awk', 'tail', 'dmesg', 'read', 'netstat', 'ps']:
    add_symlink(entries, f'bin/{cmd}', 'busybox')

# Libraries
add_file(entries, 'lib/ld-musl-aarch64.so.1', base / 'lib' / 'ld-musl-aarch64.so.1', 0o100755)
add_symlink(entries, 'lib/libc.musl-aarch64.so.1', 'ld-musl-aarch64.so.1')

# Kernel modules - modules are in the modloop-virt-extract directory
modbase = Path('/tmp/modloop-virt-extract/modules/6.6.110-0-virt/kernel')
needed_modules = [
    ('drivers/virtio', 'virtio_mmio.ko'),
    ('net/vmw_vsock', 'vsock.ko'),
    ('net/vmw_vsock', 'vmw_vsock_virtio_transport_common.ko'),
    ('net/vmw_vsock', 'vmw_vsock_virtio_transport.ko'),
]

created_dirs = set()
for dirname, modname in needed_modules:
    parts = dirname.split('/')
    for i in range(len(parts)):
        dirpath = '/'.join(parts[:i+1])
        fulldir = f'lib/modules/6.6.110-0-virt/kernel/{dirpath}'
        if fulldir not in created_dirs:
            add_dir(entries, fulldir)
            created_dirs.add(fulldir)
    
    modpath = modbase / dirname / modname
    if modpath.exists():
        add_file(entries, f'lib/modules/6.6.110-0-virt/kernel/{dirname}/{modname}', modpath, 0o100644)
    else:
        print(f"Warning: {modpath} not found")

# Trailer
add_entry(entries, 'TRAILER!!!', 0)

cpio_data = b''.join(entries)
with gzip.open('/tmp/initramfs-final.cpio.gz', 'wb') as f:
    f.write(cpio_data)

print(f"Created /tmp/initramfs-final.cpio.gz ({len(cpio_data)} bytes uncompressed)")
