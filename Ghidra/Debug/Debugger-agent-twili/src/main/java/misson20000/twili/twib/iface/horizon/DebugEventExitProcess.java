package misson20000.twili.twib.iface.horizon;

import java.nio.ByteBuffer;

public class DebugEventExitProcess extends DebugEvent {
	public final ProcessExitReason reason;

	public DebugEventExitProcess(int eventFlags, long eventThreadId, ProcessExitReason reason) {
		super(eventFlags, eventThreadId);
		this.reason = reason;
	}

	public static DebugEventExitProcess deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
		ProcessExitReason reason = ProcessExitReason.values()[buf.getInt()];
		
		return new DebugEventExitProcess(eventFlags, eventThreadId, reason);
	}
	
	@Override
	public DebugEventType getDebugEventType() {
		return DebugEventType.ExitProcess;
	}
}
