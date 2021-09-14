package misson20000.twili.twib.iface.horizon;

import java.nio.ByteBuffer;

import ghidra.util.exception.NotYetImplementedException;

public enum DebugExceptionType {
	UndefinedInstruction {
		@Override
		public DebugEventException deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
			throw new NotYetImplementedException();
		}
	}, InstructionAbort {
		@Override
		public DebugEventException deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
			throw new NotYetImplementedException();
		}
	}, DataAbort {
		@Override
		public DebugEventException deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
			throw new NotYetImplementedException();
		}
	}, AlignmentFault {
		@Override
		public DebugEventException deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
			throw new NotYetImplementedException();
		}
	}, DebuggerAttached {
		@Override
		public DebugEventException deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
			return DebugExceptionDebuggerAttached.deserialize(buf, eventFlags, eventThreadId);
		}
	}, BreakPoint {
		@Override
		public DebugEventException deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
			throw new NotYetImplementedException();
		}
	}, UserBreak {
		@Override
		public DebugEventException deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
			throw new NotYetImplementedException();
		}
	}, DebuggerBreak {
		@Override
		public DebugEventException deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
			throw new NotYetImplementedException();
		}
	}, UndefinedSystemCall {
		@Override
		public DebugEventException deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
			throw new NotYetImplementedException();
		}
	}, MemorySystemError {
		@Override
		public DebugEventException deserialize(ByteBuffer buf, int eventFlags, long eventThreadId) {
			throw new NotYetImplementedException();
		}
	};
	
	public static DebugExceptionType get(int ordinal) throws UnrecognizedDebugExceptionTypeException {
		if(ordinal >= DebugExceptionType.values().length) {
			throw new UnrecognizedDebugExceptionTypeException(ordinal);
		} else {
			return DebugExceptionType.values()[ordinal];
		}
	}

	public abstract DebugEventException deserialize(ByteBuffer buf, int eventFlags, long eventThreadId);
}
