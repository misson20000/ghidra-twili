package misson20000.twili.twib.iface.horizon;

import java.nio.ByteBuffer;

public class DebugEventCreateProcess extends DebugEvent {
	public final long programId;
	public final long processId;
	public final String name;
	public final int createProcessFlags;
	public final long userExceptionContextAddress;

	public DebugEventCreateProcess(int eventFlags, long eventThreadId, long programId, long processId, String name,
			int createProcessFlags, long userExceptionContextAddress) {
		super(eventFlags, eventThreadId);
		this.programId = programId;
		this.processId = processId;
		this.name = name;
		this.createProcessFlags = createProcessFlags;
		this.userExceptionContextAddress = userExceptionContextAddress;
	}

	public static DebugEventCreateProcess deserialize(ByteBuffer payload, int eventFlags, long eventThreadId) {
		long programId = payload.getLong();
		long processId = payload.getLong();
		
		byte[] nameBytes = new byte[0xc];
		payload.get(nameBytes);
		
		int nameLength;
		for(nameLength = 0; nameBytes[nameLength] != 0; nameLength++) {}
		String name = new String(nameBytes, 0, nameLength);
		
		int createProcessFlags = payload.getInt();
		long userExceptionContextAddress = payload.getLong();
		
		return new DebugEventCreateProcess(eventFlags, eventThreadId, programId, processId, name,
				createProcessFlags, userExceptionContextAddress);
	}
	
	@Override
	public DebugEventType getDebugEventType() {
		return DebugEventType.CreateProcess;
	}
}
