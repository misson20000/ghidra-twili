package misson20000.twili.twib.iface;

import java.util.concurrent.CompletableFuture;

import misson20000.twili.twib.iface.horizon.DebugEvent;
import misson20000.twili.twib.iface.horizon.MemoryInfo;

public interface ITwibDebugger {
	CompletableFuture<MemoryInfo> queryMemory(long addr);
	CompletableFuture<byte[]> readMemory(long addr, long size);
	CompletableFuture<Void> writeMemory(long addr, byte[] data);
	CompletableFuture<DebugEvent> getDebugEvent();
	CompletableFuture<byte[]> getThreadContext(long threadId);
	CompletableFuture<Void> setThreadContext(long threadId, byte[] context);
}
