package misson20000.twili.twib.iface.impl;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.stream.Collectors;

import org.msgpack.core.MessagePack;
import org.msgpack.value.MapValue;
import org.msgpack.value.Value;

import misson20000.twili.twib.TwibObject;
import misson20000.twili.twib.iface.ITwibDeviceInterface;
import misson20000.twili.twib.iface.ITwibMetaInterface;
import misson20000.twili.twib.transport.TwibTransport;

public class TwibMetaInterfaceImpl extends TwibObject implements ITwibMetaInterface {
	public TwibMetaInterfaceImpl(TwibTransport transport, long deviceId, int objectId) {
		super(transport, deviceId, objectId);
	}

	@Override
	public CompletableFuture<List<Device>> listDevices() {
		return this.sendRequest(10, emptyBuffer).thenCompose(Response::composeAssertOk).thenApply((rs) -> {
			try {
				long packSize = rs.payload.getLong();
				
				rs.payload.limit((int) (rs.payload.position() + packSize));
				
				Value v = MessagePack.newDefaultUnpacker(rs.payload).unpackValue();
				return v.asArrayValue().list().stream().map(pack -> {
					return new DeviceImpl(pack.asMapValue());
				}).collect(Collectors.toList());
			} catch (IOException e) {
				throw new CompletionException(e);
			}
		});
	}

	public class DeviceImpl extends Device {
		public DeviceImpl(MapValue v) {
			super(v);
		}

		@Override
		public ITwibDeviceInterface open() {
			return new TwibDeviceInterfaceImpl(transport, this.deviceId, 0);
		}
	}
	
	@Override
	public void close() {
		// no-op; can't close meta interface
	}
}
