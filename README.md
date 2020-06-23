#HOWTO

## Build library
```
cd lib
make
```

or enable RDMA:
```
make USE_RDMA=1
```

or enable debug(flood of log):
```
make DEBUG=1
```

or enable memory leak test:
```
make MALLOC_DEBUG=1 USE_RDMA
MALLOC_TRACE=/dev/shm ./nvmf-fio --filename=rdma://192.168.122.33:4420/nvmet-always/1 --randrw --iodepth=32 --ioqueues=4 --runtime=3

../scripts/checkleak.py /dev/shm/nvmf_mtrace_53826
```

## Test
### Run a target
```
modprobe nvmet-tcp

# create a target
mkdir /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp
echo 1 > /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp/attr_allow_any_host
echo 0123456789abcdef > /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp/attr_serial

sleep 0.1
mkdir /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp/namespaces/1
# select your image path
echo "/nvme/nvme.img" > /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp/namespaces/1/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp/namespaces/1/enable

sleep 0.1
mkdir /sys/kernel/config/nvmet/ports/2
echo ipv4 > /sys/kernel/config/nvmet/ports/2/addr_adrfam
echo "192.168.122.33" > /sys/kernel/config/nvmet/ports/2/addr_traddr
echo 4420 > /sys/kernel/config/nvmet/ports/2/addr_trsvcid
echo tcp > /sys/kernel/config/nvmet/ports/2/addr_trtype
ln -s /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp/ /sys/kernel/config/nvmet/ports/2/subsystems/nvmet-always-tcp

```

### Run nvmf-fio example
```
cd examples
make fio

./nvmf-fio --filename=nvmf-tcp://192.168.122.33:4420/nvmet-always-tcp/1 --randrw --iodepth=32 --ioqueues=4 --runtime=100

Or run rdma:
./nvmf-fio --filename=nvmf-rdma://192.168.122.33:4420/nvmet-always-rdma/1 --randrw --iodepth=32 --ioqueues=4 --runtime=100
```

### Test reconnect TCP
On target side:
```
iptables -A INPUT -p tcp --dport 4420 -j DROP; sleep 6; dmesg -T -c; iptables -F
```

### Test reconnect RDMA
On target side (RXE case):
```
iptables -A INPUT -p udp --dport 4791 -j DROP; sleep 6; dmesg -T -c; iptables -F
```
