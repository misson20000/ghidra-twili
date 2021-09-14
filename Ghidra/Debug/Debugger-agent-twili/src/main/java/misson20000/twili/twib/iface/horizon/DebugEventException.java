package misson20000.twili.twib.iface.horizon;

import java.nio.ByteBuffer;

public abstract class DebugEventException extends DebugEvent {
	protected DebugEventException(int eventFlags, long eventThreadId) {
		super(eventFlags, eventThreadId);
	}

	public static DebugEventException deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) throws UnrecognizedDebugExceptionTypeException {
		return DebugExceptionType.get(buf.getInt()).deserialize(buf, eventFlags, eventThreadId);
	}

	@Override
	public DebugEventType getDebugEventType() {
		return DebugEventType.Exception;
	}
	
	public abstract DebugExceptionType getDebugExceptionType();
}
