package misson20000.twili.twib.iface.impl;

import java.nio.ByteOrder;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import misson20000.twili.twib.TwibObject;
import misson20000.twili.twib.iface.ITwibDebugger;
import misson20000.twili.twib.iface.ITwibDeviceInterface;
import misson20000.twili.twib.transport.TwibTransport;

public class TwibDeviceInterfaceImpl extends TwibObject implements ITwibDeviceInterface {
	public TwibDeviceInterfaceImpl(TwibTransport transport, long deviceId, int objectId) {
		super(transport, deviceId, objectId);
	}

	@Override
	public CompletableFuture<List<ProcessListEntry>> listProcesses() {
		return this.sendRequest(14, emptyBuffer).thenCompose(Response::composeAssertOk).thenApply((rs) -> {
			long count = rs.payload.getLong();
			
			return IntStream.range(0, (int) count).mapToObj(__ -> {
				long processId = rs.payload.getLong();
				int result = rs.payload.getInt();
				rs.payload.position(rs.payload.position() + 4); // padding
				long titleId = rs.payload.getLong();
				byte processName[] = new byte[12];
				rs.payload.get(processName);
				int mmuFlags = rs.payload.getInt();
				
				int processNameLength;
				for(processNameLength = 0; processName[processNameLength] != 0; processNameLength++) {}
				
				return new ProcessListEntry(processId, result, titleId, new String(processName, 0, processNameLength), mmuFlags);
			}).collect(Collectors.toList());
		});
	}

	@Override
	public CompletableFuture<ITwibDebugger> openActiveDebugger(long pid) {
		ByteBuffer payload = ByteBuffer.allocate(8);
		payload.order(ByteOrder.LITTLE_ENDIAN);
		payload.putLong(pid);
		payload.flip();
		
		return this.sendRequest(19, payload).thenCompose(Response::composeAssertOk).thenApply((rs) -> {
			return rs.newChild(TwibDebuggerImpl::new, 0);
		});
	}
}
