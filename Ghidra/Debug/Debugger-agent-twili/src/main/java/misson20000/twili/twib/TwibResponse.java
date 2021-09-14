package misson20000.twili.twib;

import java.nio.ByteBuffer;

public class TwibResponse {
	public TwibResponse(int deviceId, int objectId, int resultCode, int tag, ByteBuffer payload, int[] objects) {
		this.deviceId = deviceId;
		this.objectId = objectId;
		this.resultCode = resultCode;
		this.tag = tag;
		this.payload = payload;
		this.objects = objects;
	}
	
	public int deviceId;
	public int objectId;
	public int resultCode;
	public int tag;
	public ByteBuffer payload;
	public int[] objects;
}
