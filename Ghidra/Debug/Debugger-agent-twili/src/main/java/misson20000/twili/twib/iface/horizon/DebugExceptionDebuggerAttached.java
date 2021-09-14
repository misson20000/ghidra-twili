package misson20000.twili.twib.iface.horizon;

import java.nio.ByteBuffer;

public class DebugExceptionDebuggerAttached extends DebugEventException {
	protected DebugExceptionDebuggerAttached(int eventFlags, long eventThreadId) {
		super(eventFlags, eventThreadId);
	}
	
	public static DebugExceptionDebuggerAttached deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
		return new DebugExceptionDebuggerAttached(eventFlags, eventThreadId);
	}

	@Override
	public DebugExceptionType getDebugExceptionType() {
		return DebugExceptionType.DebuggerAttached;
	}
}
