package misson20000.twili.twib.transport;

import java.util.concurrent.CompletableFuture;

import misson20000.twili.twib.TwibRequest;
import misson20000.twili.twib.TwibResponse;

public interface TwibTransport {
	CompletableFuture<TwibResponse> sendRequest(TwibRequest request);
}
