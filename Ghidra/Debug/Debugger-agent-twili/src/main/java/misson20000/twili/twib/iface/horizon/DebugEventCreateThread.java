package misson20000.twili.twib.iface.horizon;

import java.nio.ByteBuffer;

public class DebugEventCreateThread extends DebugEvent {
	public final long threadId;
	public final long tlsAddress;
	
	public DebugEventCreateThread(int eventFlags, long eventThreadId, long threadId, long tlsAddress) {
		super(eventFlags, eventThreadId);
		this.threadId = threadId;
		this.tlsAddress = tlsAddress;
	}

	public static DebugEventCreateThread deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
		long threadId = buf.getLong();
		long tlsAddress = buf.getLong();
		
		return new DebugEventCreateThread(eventFlags, eventThreadId, threadId, tlsAddress);
	}
	
	@Override
	public DebugEventType getDebugEventType() {
		return DebugEventType.CreateThread;
	}
}
