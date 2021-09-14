package misson20000.twili.twib.iface.impl;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import misson20000.twili.twib.TwibObject;
import misson20000.twili.twib.iface.ITwibDebugger;
import misson20000.twili.twib.iface.horizon.DebugEvent;
import misson20000.twili.twib.iface.horizon.MemoryInfo;
import misson20000.twili.twib.iface.horizon.UnrecognizedDebugEventTypeException;
import misson20000.twili.twib.iface.horizon.UnrecognizedDebugExceptionTypeException;
import misson20000.twili.twib.transport.TwibTransport;

public class TwibDebuggerImpl extends TwibObject implements ITwibDebugger {
	public TwibDebuggerImpl(TwibTransport transport, long deviceId, int objectId) {
		super(transport, deviceId, objectId);
	}

	@Override
	public CompletableFuture<MemoryInfo> queryMemory(long addr) {
		ByteBuffer payload = ByteBuffer.allocate(8);
		payload.order(ByteOrder.LITTLE_ENDIAN);
		payload.putLong(addr);
		payload.flip();
		
		return this.sendRequest(10, payload).thenCompose(Response::composeAssertOk).thenApply((rs) -> {
			return MemoryInfo.deserialize(rs.payload);
		});
	}

	@Override
	public CompletableFuture<byte[]> readMemory(long addr, long size) {
		ByteBuffer payload = ByteBuffer.allocate(16);
		payload.order(ByteOrder.LITTLE_ENDIAN);
		payload.putLong(addr);
		payload.putLong(size);
		payload.flip();
		
		return this.sendRequest(11, payload).thenCompose(Response::composeAssertOk).thenApply((rs) -> {
			long actualSize = rs.payload.getLong();
			byte[] bytes = new byte[(int) actualSize];
			rs.payload.get(bytes);
			return bytes;
		});
	}

	@Override
	public CompletableFuture<Void> writeMemory(long addr, byte[] data) {
		ByteBuffer payload = ByteBuffer.allocate(16 + data.length);
		payload.order(ByteOrder.LITTLE_ENDIAN);
		payload.putLong(addr);
		payload.putLong(data.length);
		payload.put(data);
		payload.flip();
		
		return this.sendRequest(12, payload).thenCompose(Response::composeAssertOk).thenAccept((rs) -> { });
	}
	
	@Override
	public CompletableFuture<DebugEvent> getDebugEvent() {
		return this.sendRequest(14, emptyBuffer).thenCompose(rs -> {
			if(rs.resultCode == 0x8c01) {
				return CompletableFuture.completedFuture(null); // signal no events left with null
			} else {
				return rs.composeAssertOk();
			}
		}).thenApply(rs -> {
			try {
				if(rs != null) {
					return DebugEvent.deserialize(rs.payload);
				} else {
					return null;
				}
			} catch (UnrecognizedDebugEventTypeException | UnrecognizedDebugExceptionTypeException e) {
				throw new CompletionException(e);
			}
		});
	}

	@Override
	public CompletableFuture<byte[]> getThreadContext(long threadId) {
		ByteBuffer payload = ByteBuffer.allocate(8);
		payload.order(ByteOrder.LITTLE_ENDIAN);
		payload.putLong(threadId);
		payload.flip();
		
		return this.sendRequest(15, payload).thenCompose(Response::composeAssertOk).thenApply(rs -> {
			byte[] context = new byte[0x320];
			rs.payload.get(context);
			return context;
		});
	}
	
	@Override
	public CompletableFuture<Void> setThreadContext(long threadId, byte[] context) {
		if(context.length != 0x320) {
			throw new IllegalArgumentException("expected thread context length to be 0x320 (was 0x" + Integer.toHexString(context.length) + ")");
		}
		
		ByteBuffer payload = ByteBuffer.allocate(0x320 + 12);
		payload.order(ByteOrder.LITTLE_ENDIAN);
		payload.putLong(threadId);
		payload.putInt(15);
		payload.put(context);
		payload.flip();
		
		return this.sendRequest(18, payload).thenCompose(Response::composeAssertOk).thenApply(__ -> null);
	}
}
