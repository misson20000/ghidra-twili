package misson20000.twili.twib;

import java.nio.ByteBuffer;

public class TwibRequest {
	public long deviceId;
	public int objectId;
	public int commandId;
	public int tag;
	public ByteBuffer payload; // payload contents should be remaining
	
	public TwibRequest(long deviceId, int objectId, int commandId, int tag, ByteBuffer payload) {
		this.deviceId = deviceId;
		this.objectId = objectId;
		this.commandId = commandId;
		this.tag = tag;
		this.payload = payload;
	}
}
