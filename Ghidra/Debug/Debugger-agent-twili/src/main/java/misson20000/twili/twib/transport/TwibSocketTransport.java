package misson20000.twili.twib.transport;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import misson20000.twili.twib.TwibRequest;
import misson20000.twili.twib.TwibResponse;

public class TwibSocketTransport implements TwibTransport, AutoCloseable {
	private CompletableFuture<Void> lastWrite = AsyncUtils.NIL;
	
	private static final int HEADER_LENGTH = 32; // includes 4 bytes padding
	private ByteBuffer requestHeaderBuffer = ByteBuffer.allocate(HEADER_LENGTH);
	private ByteBuffer responseHeaderBuffer = ByteBuffer.allocate(HEADER_LENGTH);
	
	private ConcurrentMap<Integer, CompletableFuture<TwibResponse>> outstandingRequests = new ConcurrentHashMap<>();
	
	private AsynchronousSocketChannel socket;
	
	private Random tagGenerator = new Random();

	private static final CompletionHandler<Long, CompletableFuture<Long>> longCompletionHandler = new CompletionHandler<>() {
		@Override
		public void completed(Long val, CompletableFuture<Long> future) {
			future.complete(val);
		}

		@Override
		public void failed(Throwable val, CompletableFuture<Long> future) {
			future.completeExceptionally(val);
		}
	};
	
	private static final CompletionHandler<Integer, CompletableFuture<Integer>> integerCompletionHandler = new CompletionHandler<>() {
		@Override
		public void completed(Integer val, CompletableFuture<Integer> future) {
			future.complete(val);
		}

		@Override
		public void failed(Throwable val, CompletableFuture<Integer> future) {
			future.completeExceptionally(val);
		}
	};
	
	public TwibSocketTransport(AsynchronousSocketChannel socket) {
		this.socket = socket;
		
		AsyncUtils.loop(TypeSpec.VOID, loop -> {
			responseHeaderBuffer.clear();
			
			CompletableFuture<Integer> readHeaderFuture = new CompletableFuture<>();
			
			socket.read(responseHeaderBuffer, readHeaderFuture, integerCompletionHandler);

			readHeaderFuture.thenCompose(sz1 -> {
				responseHeaderBuffer.flip();

				if(sz1 != HEADER_LENGTH || responseHeaderBuffer.remaining() != HEADER_LENGTH) {
					return CompletableFuture.failedFuture(new Exception("couldn't read entire header"));
				}
				
				responseHeaderBuffer.order(ByteOrder.LITTLE_ENDIAN);
				int deviceId = responseHeaderBuffer.getInt();
				int objectId = responseHeaderBuffer.getInt();
				int resultCode = responseHeaderBuffer.getInt();
				int tag = responseHeaderBuffer.getInt();
				long payloadSize = responseHeaderBuffer.getLong();
				int objectCount = responseHeaderBuffer.getInt();
				
				ByteBuffer payload = ByteBuffer.allocate((int) payloadSize);
				ByteBuffer objects = ByteBuffer.allocate(objectCount * 4);
				
				CompletableFuture<Long> readBodyFuture = new CompletableFuture<>();
				
				socket.read(new ByteBuffer[] {payload, objects}, 0, 2, 5L, TimeUnit.SECONDS, readBodyFuture, longCompletionHandler);
				
				return readBodyFuture.thenCompose(sz2 -> {
					payload.flip();
					objects.flip();
					
					if(sz2 != payloadSize + (objectCount * 4) || payload.remaining() != payloadSize || objects.remaining() != (objectCount * 4)) {
						return CompletableFuture.failedFuture(new Exception("couldn't read entire body"));
					}
					
					int[] objectsArray = new int[objectCount];
					objects.order(ByteOrder.LITTLE_ENDIAN);
					objects.asIntBuffer().get(objectsArray);
					
					return CompletableFuture.completedFuture(new TwibResponse(
						deviceId,
						objectId,
						resultCode,
						tag,
						payload,
						objectsArray
					));
				});
			}).handle(loop::consume);
		}, TypeSpec.cls(TwibResponse.class), (data, loop) -> {
			CompletableFuture<TwibResponse> outstandingRequest = outstandingRequests.remove(data.tag);
			
			if(outstandingRequest == null) {
				loop.exit(new Exception("got response with an unknown tag"));
			} else {
				loop.repeat();
				outstandingRequest.complete(data);
			}
		}).exceptionally(ex -> {
			// When an error occurs (including socket closure), fail all the outstanding requests.
			outstandingRequests.forEach((tag, response) -> {
				response.completeExceptionally(ex);
			});
			
			return null;
		});
	}

	@Override
	public synchronized CompletableFuture<TwibResponse> sendRequest(TwibRequest request) {
		CompletableFuture<TwibResponse> future = new CompletableFuture<>();
		int payloadLength = request.payload.remaining();
		
		// Generate a new tag
		do {
			request.tag = tagGenerator.nextInt();
		} while(outstandingRequests.containsKey(request.tag)); // on the off-chance that we get a collision, regenerate the tag
		
		outstandingRequests.put(request.tag, future);
		
		// We chain write futures together so that we don't write while a previous write is pending.
		lastWrite = lastWrite.thenCompose(__ -> {
			requestHeaderBuffer.clear();
			requestHeaderBuffer.order(ByteOrder.LITTLE_ENDIAN);
			requestHeaderBuffer.putLong(request.deviceId);
			requestHeaderBuffer.position(requestHeaderBuffer.position() - 4); // roll back four bytes... deviceId is actually 4 bytes long
			requestHeaderBuffer.putInt(request.objectId);
			requestHeaderBuffer.putInt(request.commandId);
			requestHeaderBuffer.putInt(request.tag);
			requestHeaderBuffer.putLong(payloadLength);
			requestHeaderBuffer.putInt(0); // in objects not allowed
			requestHeaderBuffer.putInt(0); // padding
			requestHeaderBuffer.flip();
			
			//System.out.printf("sending packet: device id 0x%x object id %d command id %d\n", request.deviceId, request.objectId, request.tag);
			
			// I know AsyncUtils.completable exists for this, but it doesn't have a form for 5 parameters.
			CompletableFuture<Long> writeFuture = new CompletableFuture<>();
			
			socket.write(new ByteBuffer[] {
					requestHeaderBuffer, request.payload
			}, 0, 2, 5L, TimeUnit.SECONDS, writeFuture, longCompletionHandler);
			
			return writeFuture;
		}).thenCompose(sz -> {
			if(sz != HEADER_LENGTH + payloadLength) {
				return CompletableFuture.failedFuture(new Exception("couldn't write all bytes"));
			}
			
			return AsyncUtils.NIL;
		}).exceptionally(ex -> {
			outstandingRequests.remove(request.tag, future);
			future.completeExceptionally(ex);
			return null;
		});
		
		return future;
	}
	
	@Override
	public void close() throws Exception {
		socket.close();
	}
}
