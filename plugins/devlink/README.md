# Devlink Plugin

This plugin provides firmware update support for network interface cards that support the Linux devlink interface. This is a generic plugin that can work with any device that implements devlink functionality.

## Supported Devices

The plugin supports any device that implements the devlink interface, regardless the bus it resides on.

## How It Works

The plugin uses the Linux devlink netlink interface to communicate with the kernel and perform firmware updates. The process involves:

1. **Device Detection**: The plugin detects PCI network devices and checks if they support devlink
2. **Netlink Communication**: Establishes a generic netlink socket to communicate with the devlink subsystem
3. **Firmware Upload**: Writes the firmware file to `/lib/firmware/` and instructs devlink to flash it
4. **Progress Monitoring**: Monitors devlink status messages to provide real-time progress updates

## Requirements

- Linux kernel with devlink support (4.10+)
- Network device driver with devlink implementation
- Root privileges (required for netlink communication)

## Usage

The plugin integrates seamlessly with fwupd. Once installed, supported devices will appear in the device list:

```bash
# List devices
fwupdmgr get-devices

# Update firmware
fwupdmgr update
```

## Technical Details

### Netlink Protocol

The plugin implements the devlink generic netlink protocol:

1. **Family Resolution**: Queries the kernel for the devlink family ID
2. **Flash Command**: Sends `DEVLINK_CMD_FLASH_UPDATE` with device and file information
3. **Status Monitoring**: Receives `DEVLINK_CMD_FLASH_UPDATE_STATUS` messages for progress
4. **Completion**: Waits for `DEVLINK_CMD_FLASH_UPDATE_END` to confirm completion

### Private Flags

The plugin supports the following private flags:

#### `omit-component-name`

When this flag is set, the plugin will not include the `DEVLINK_ATTR_FLASH_UPDATE_COMPONENT` attribute in the flash command. This is useful for devices that don't require or support component-specific updates.

**Usage in quirk file:**
```ini
[DeviceInstanceId=PCI\VEN_XXXX&DEV_YYYY]
Plugin = devlink
Flags = omit-component-name
```

**Usage in metainfo XML:**
```xml
<custom>
  <value key="LVFS::DeviceFlags">omit-component-name</value>
</custom>
```

### Device Identification

Devices are identified using their PCI bus location in the format:
```
pci/0000:01:00.0
```

Where:
- `0000` is the PCI domain
- `01` is the bus number
- `00` is the device number
- `0` is the function number

### Error Handling

The plugin handles various error conditions:
- Kernel without devlink support
- Device without devlink capability
- Firmware file access issues
- Flash operation failures

## Debugging

Enable debug logging to troubleshoot issues:

```bash
fwupdmgr --verbose update
```

This will show detailed netlink communication and device detection information.

## Security Considerations

- Firmware files are temporarily stored in `/lib/firmware/`
- Root privileges are required for netlink socket operations
- The plugin validates device support before attempting updates
- Temporary files are cleaned up after the operation

## Contributing

When adding support for new devices:

1. Add the device ID to `devlink-flash.quirk`
2. Test with the specific device
3. Update this README with the new device information

## References

- [Linux Devlink Documentation](https://www.kernel.org/doc/html/latest/networking/devlink/)
- [Netlink Protocol](https://man7.org/linux/man-pages/man7/netlink.7.html)
- [Generic Netlink](https://www.kernel.org/doc/html/latest/userspace-api/netlink/intro.html)
