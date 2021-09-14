package misson20000.twili.twib.iface.horizon;

import java.nio.ByteBuffer;

public abstract class DebugEvent {
	public final int eventFlags;
	public final long eventThreadId;
	
	protected DebugEvent(int eventFlags, long eventThreadId) {
		this.eventFlags = eventFlags;
		this.eventThreadId = eventThreadId;
	}

	public static enum DebugEventType {		
		CreateProcess {
			@Override
			public DebugEvent deserialize(ByteBuffer buf, int flags, long threadId) {
				return DebugEventCreateProcess.deserialize(buf, flags, threadId);
			}
		}, CreateThread {
			@Override
			public DebugEvent deserialize(ByteBuffer buf, int flags, long threadId) {
				return DebugEventCreateThread.deserialize(buf, flags, threadId);
			}
		}, ExitProcess {
			@Override
			public DebugEvent deserialize(ByteBuffer buf, int flags, long threadId) {
				return DebugEventExitProcess.deserialize(buf, flags, threadId);
			}
		}, ExitThread {
			@Override
			public DebugEvent deserialize(ByteBuffer buf, int flags, long threadId) {
				return DebugEventExitThread.deserialize(buf, flags, threadId);
			}
		}, Exception {
			@Override
			public DebugEvent deserialize(ByteBuffer buf, int flags, long threadId) throws UnrecognizedDebugExceptionTypeException {
				return DebugEventException.deserialize(buf, flags, threadId);
			}
		};
		
		public abstract DebugEvent deserialize(ByteBuffer buf, int flags, long threadId) throws UnrecognizedDebugExceptionTypeException;
		
		public static DebugEventType get(int ordinal) throws UnrecognizedDebugEventTypeException {
			if(ordinal >= DebugEventType.values().length) {
				throw new UnrecognizedDebugEventTypeException(ordinal);
			} else {
				return DebugEventType.values()[ordinal];
			}
		}
	}
	
	public static DebugEvent deserialize(ByteBuffer buf) throws UnrecognizedDebugEventTypeException, UnrecognizedDebugExceptionTypeException {
		int type = buf.getInt();
		int flags = buf.getInt();
		long threadId = buf.getLong();
		
		return DebugEventType.get(type).deserialize(buf, flags, threadId);
	}
	
	public abstract DebugEventType getDebugEventType();
}
