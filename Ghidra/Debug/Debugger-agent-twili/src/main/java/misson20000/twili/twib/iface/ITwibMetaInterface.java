package misson20000.twili.twib.iface;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.msgpack.value.MapValue;

public interface ITwibMetaInterface extends AutoCloseable {
	CompletableFuture<List<Device>> listDevices();
	
	public static class Identification {
		public String service = null;
		public int protocol = 0;
		public byte[] firmware_version = null;
		public String serial_number = null;
		public byte[] bluetooth_bd_address = null;
		public byte[] wireless_lan_mac_address = null;
		public String device_nickname = null;
		public byte[] mii_author_id = null;
		
		public Identification(MapValue v) {
			v.entrySet().forEach(entry -> {
				switch(entry.getKey().asStringValue().asString()) {
				case "service":
					this.service = entry.getValue().asStringValue().asString();
					break;
				case "protocol":
					this.protocol = entry.getValue().asIntegerValue().asInt();
					break;
				case "firmware_version":
					this.firmware_version = entry.getValue().asBinaryValue().asByteArray();
					break;
				case "serial_number":
					this.serial_number = entry.getValue().asStringValue().asString();
					break;
				case "bluetooth_bd_address":
					this.bluetooth_bd_address = entry.getValue().asBinaryValue().asByteArray();
					break;
				case "wireless_lan_mac_address":
					this.wireless_lan_mac_address = entry.getValue().asBinaryValue().asByteArray();
					break;
				case "device_nickname":
					this.device_nickname = entry.getValue().asStringValue().asString();
					break;
				case "mii_author_id":
					this.mii_author_id = entry.getValue().asBinaryValue().asByteArray();
					break;
				default:
					// interesting; got an unknown ident field
					break;
				}
			});
		}
		
		public String getHumanReadableFirmwareVersion() {
			int length;
			for(length = 0; firmware_version[0x68 + length] != 0; length++) {}
			return new String(this.firmware_version, 0x68, length);
		}
	}
	
	public static abstract class Device {
		public long deviceId;
		public String bridgeType;
		public Identification identification;
		
		public Device(MapValue v) {
			v.entrySet().forEach(entry -> {
				switch(entry.getKey().asStringValue().asString()) {
				case "device_id":
					this.deviceId = entry.getValue().asIntegerValue().asLong();
					break;
				case "bridge_type":
					this.bridgeType = entry.getValue().asStringValue().asString();
					break;
				case "identification":
					this.identification = new Identification(entry.getValue().asMapValue());
					break;
				default:
					break;
				}
			});
		}
		
		public String toString() {
			return String.format("Device (id %08x, bridge type %s, firmware version %s, nickname %s)", deviceId, bridgeType, identification.getHumanReadableFirmwareVersion(), identification.device_nickname);
		}
		
		public abstract ITwibDeviceInterface open();
	}
}
