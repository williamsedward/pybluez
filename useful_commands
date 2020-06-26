hciconfig hci0 up
hciconfig hci0 down

sudo gatttool -t random -b AC:23:3F:66:47:7D --char-write-req -a 0x5001 -n 0x70110204 --listen
sudo hcitool lescan | grep KLK
sudo gatttool -t random -b AC:23:3F:66:47:7D -I

0x14

bluetoothctl

power off
power on
agent on
scan on
scan off
info <MA:C0:0A:DD:RE:SS>

sed sudo nano /lib/systemd/system/bluetooth.service

ExecStart=/usr/lib/bluetooth/bluetoothd --experimental
append experiemtnal in bluetooth.service with sed --------------

THIS WORKS

sudo hcitool lescan
sudo hcitool lecc AC:23:3F:66:47:7D
bluetoothctl
pair
123456
info
select-attribute c5cc5000-127f-45ac-b0fc-7e46c3591334

