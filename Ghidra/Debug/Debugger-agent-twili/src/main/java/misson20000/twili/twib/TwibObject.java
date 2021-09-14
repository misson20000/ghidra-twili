package misson20000.twili.twib;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.CompletableFuture;

import misson20000.twili.twib.transport.TwibTransport;

public abstract class TwibObject implements AutoCloseable {
	protected TwibTransport transport;
	protected long deviceId;
	protected int objectId;
	
	protected static final ByteBuffer emptyBuffer = ByteBuffer.allocate(0);

	protected TwibObject(TwibTransport transport, long deviceId, int objectId) {
		this.transport = transport;
		this.deviceId = deviceId;
		this.objectId = objectId;
	}
	
	protected CompletableFuture<Response> sendRequest(int commandId, ByteBuffer payload) {
		TwibRequest rq = new TwibRequest(deviceId, objectId, commandId, 0, payload); // tag is clobbered by transport
		
		return transport.sendRequest(rq).thenApply(Response::new);
	}
	
	protected static interface ObjectProducer<T> {
		T produce(TwibTransport transport, long deviceId, int objectId);
	}
	
	protected class Response {
		public final int resultCode;
		public final ByteBuffer payload;
		public final int[] objects;
		
		public Response(TwibResponse rs) {
			rs.payload.order(ByteOrder.LITTLE_ENDIAN);
			
			this.resultCode = rs.resultCode;
			this.payload = rs.payload;
			this.objects = rs.objects;
		}
		
		public <T> T newChild(ObjectProducer<T> prod, int index) {
			return prod.produce(transport, deviceId, objects[index]);
		}
		
		public void assertOk() throws TwibResultException {
			if(resultCode != 0) {
				throw new TwibResultException(resultCode);
			}
		}
		
		public CompletableFuture<Response> composeAssertOk() {
			if(resultCode != 0) {
				return CompletableFuture.failedFuture(new TwibResultException(resultCode));
			} else {
				return CompletableFuture.completedFuture(this);
			}
		}
	}
	
	@Override
	public void close() throws Exception {
		transport.sendRequest(new TwibRequest(deviceId, objectId, 0xffffffff, 0, null)).get();
	}
}
