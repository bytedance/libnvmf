modprobe nvmet-tcp

# create a target
mkdir -p /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp
echo 1 > /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp/attr_allow_any_host
echo 0123456789abcdef > /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp/attr_serial

sleep 0.1
mkdir -p /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp/namespaces/1
# select your image path
echo "/data04/nvme.img" > /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp/namespaces/1/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp/namespaces/1/enable

sleep 0.1
mkdir -p /sys/kernel/config/nvmet/ports/2
echo ipv4 > /sys/kernel/config/nvmet/ports/2/addr_adrfam
echo "10.156.69.77" > /sys/kernel/config/nvmet/ports/2/addr_traddr
echo 4420 > /sys/kernel/config/nvmet/ports/2/addr_trsvcid
echo tcp > /sys/kernel/config/nvmet/ports/2/addr_trtype
ln -s /sys/kernel/config/nvmet/subsystems/nvmet-always-tcp/ /sys/kernel/config/nvmet/ports/2/subsystems/nvmet-always-tcp

#./nvmf-check nvmf-tcp://10.156.69.77:4420/nvmet-always-tcp/1
