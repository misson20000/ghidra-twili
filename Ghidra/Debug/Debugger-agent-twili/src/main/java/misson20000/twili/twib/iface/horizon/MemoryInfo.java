package misson20000.twili.twib.iface.horizon;

import java.nio.ByteBuffer;

public class MemoryInfo {
	public final long addr;
	public final long size;
	public final MemoryState state;
	public final int attribute;
	public final int permission;
	public final int ipcRefCount;
	public final int deviceRefCount;
	
	public static final int MEMORY_ATTRIBUTE_LOCKED        = 1 << 0;
	public static final int MEMORY_ATTRIBUTE_IPC_LOCKED    = 1 << 1;
	public static final int MEMORY_ATTRIBUTE_DEVICE_SHARED = 1 << 2;
	public static final int MEMORY_ATTRIBUTE_UNCACHED      = 1 << 3;
	
	public static final int MEMORY_PERMISSION_READ    = 1 << 0;
	public static final int MEMORY_PERMISSION_WRITE   = 1 << 1;
	public static final int MEMORY_PERMISSION_EXECUTE = 1 << 2;
	
	public enum MemoryState {
		Free,
		Io,
		Static,
		Code,
		CodeData,
		Normal,
		Shared,
		Alias,
		AliasCode,
		AliasCodeData,
		Ipc,
		Stack,
		ThreadLocal,
		Transfered, // [sic]
		SharedTransfered,
		SharedCode,
		Inaccessible,
		NonSecureIpc,
		NonDeviceIpc,
		Kernel,
		GeneratedCode,
		CodeOut
	}

	public MemoryInfo(long addr, long size, MemoryState state, int attribute, int permission, int ipcRefCount,
			int deviceRefCount) {
		this.addr = addr;
		this.size = size;
		this.state = state;
		this.attribute = attribute;
		this.permission = permission;
		this.ipcRefCount = ipcRefCount;
		this.deviceRefCount = deviceRefCount;
	}

	public static MemoryInfo deserialize(ByteBuffer buf) {
		long addr = buf.getLong();
		long size = buf.getLong();
		MemoryState state = MemoryState.values()[buf.getInt()];
		int attribute = buf.getInt();
		int permission = buf.getInt();
		int ipcRefCount = buf.getInt();
		int deviceRefCount = buf.getInt();
		
		return new MemoryInfo(addr, size, state, attribute, permission, ipcRefCount, deviceRefCount);
	}
}
