package agent.twili;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import agent.twili.model.TwiliModelImpl;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;
import misson20000.twili.twib.iface.ITwibMetaInterface;
import misson20000.twili.twib.iface.impl.TwibMetaInterfaceImpl;
import misson20000.twili.twib.transport.TwibSocketTransport;

/**
 * Note this is in the testing source because it's not meant to be shipped in the release.... That
 * may change if it proves stable, though, no?
 */
@FactoryDescription( //
	brief = "IN-VM Twili remote debugger", //
	htmlDetails = "Launch a twili debugger session in this same JVM" //
)
public class TwiliModelInJvmDebuggerModelFactory implements DebuggerModelFactory {

	@Override
	public CompletableFuture<? extends DebuggerObjectModel> build() {
		InetSocketAddress twibAddr = new InetSocketAddress("localhost", 64802);
		
		AsynchronousSocketChannel ch = null;
		try {
			ch = AsynchronousSocketChannel.open();
		} catch(IOException e) {
			return CompletableFuture.failedFuture(new Exception("Failed to connect to twibd", e));
		}
		
		AsynchronousSocketChannel chForLambda = ch;
		
		return AsyncUtils.completable(TypeSpec.VOID, chForLambda::connect, twibAddr).thenCompose(__ -> {
			TwibSocketTransport twibTransport = new TwibSocketTransport(chForLambda);
			ITwibMetaInterface itmi = new TwibMetaInterfaceImpl(twibTransport, 0, 0);
			
			return itmi.listDevices().whenComplete((__1, __2) -> {
				try {
					itmi.close();
				} catch (Exception e) {
					throw new CompletionException(e);
				}
			}).thenApply(devices -> {
				if(devices.size() < 1) {
					throw new CompletionException(new Exception("No devices were detected"));
				}
				
				TwiliModelImpl model = new TwiliModelImpl(devices.get(0).open());
				return model;
			});
		});
	}

}
