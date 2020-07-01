from bluetooth.ble import DiscoveryService
import sys

scan_duration=10

if len(sys.argv) > 0:
    print("scan_duration: {}".format(sys.argv[1]))
    scan_duration=int(sys.argv[1])
service = DiscoveryService()
devices = service.discover(scan_duration)

for address, name in devices.items():
    print("name: {}, address: {}".format(name, address))
