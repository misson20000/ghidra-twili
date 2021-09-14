package misson20000.twili.twib.iface.horizon;

import java.nio.ByteBuffer;

public class DebugEventExitThread extends DebugEvent {
	public final ThreadExitReason reason;

	public DebugEventExitThread(int eventFlags, long eventThreadId, ThreadExitReason reason) {
		super(eventFlags, eventThreadId);
		this.reason = reason;
	}

	public static DebugEventExitThread deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
		ThreadExitReason reason = ThreadExitReason.values()[buf.getInt()];
		
		return new DebugEventExitThread(eventFlags, eventThreadId, reason);
	}
	
	@Override
	public DebugEventType getDebugEventType() {
		return DebugEventType.ExitThread;
	}
}
