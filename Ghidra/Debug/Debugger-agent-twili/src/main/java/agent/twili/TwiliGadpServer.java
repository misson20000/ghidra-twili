package agent.twili;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.List;

import agent.twili.model.TwiliModelImpl;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.agent.AgentWindow;
import ghidra.dbg.gadp.server.AbstractGadpServer;
import misson20000.twili.twib.iface.ITwibDeviceInterface;
import misson20000.twili.twib.iface.ITwibMetaInterface;
import misson20000.twili.twib.iface.ITwibMetaInterface.Device;
import misson20000.twili.twib.iface.impl.TwibMetaInterfaceImpl;
import misson20000.twili.twib.transport.TwibSocketTransport;

public class TwiliGadpServer {
	public class GadpSide extends AbstractGadpServer {
		public GadpSide(DebuggerObjectModel model, SocketAddress addr) throws IOException {
			super(model, addr);
		}
	}

	private TwiliModelImpl model;
	private GadpSide server;
	
	public TwiliGadpServer(ITwibDeviceInterface itdi, InetSocketAddress bindTo) throws IOException {
		this.model = new TwiliModelImpl(itdi);
		this.server = new GadpSide(model, bindTo);
	}

	public static void main(String[] args) throws Exception {
		InetSocketAddress twibAddr = new InetSocketAddress("localhost", 64802);
		AsynchronousSocketChannel ch = AsynchronousSocketChannel.open();
		ch.connect(twibAddr).get();
		
		TwibSocketTransport twibTransport = new TwibSocketTransport(ch);
		
		Device device = null;
		
		try(ITwibMetaInterface itmi = new TwibMetaInterfaceImpl(twibTransport, 0, 0)) {	
			List<Device> devices = itmi.listDevices().get();
			if(devices.size() < 1) {
				throw new Exception("no devices were detected");
			}
			
			device = devices.get(0);
		}
		
		InetSocketAddress bindTo = new InetSocketAddress("localhost", 64801);
		TwiliGadpServer twidra = new TwiliGadpServer(device.open(), bindTo);
		
		twidra.launch();
	}

	private void launch() {
		this.server.launchAsyncService();
		new AgentWindow("Twili Agent for Ghidra", server.getLocalAddress());
	}
}
