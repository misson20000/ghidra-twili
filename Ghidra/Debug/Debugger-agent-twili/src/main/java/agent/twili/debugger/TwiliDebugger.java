package agent.twili.debugger;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import ghidra.util.datastruct.ListenerSet;
import misson20000.twili.twib.iface.ITwibDeviceInterface;
import misson20000.twili.twib.iface.ITwibDeviceInterface.ProcessListEntry;

public class TwiliDebugger {
	protected final ListenerSet<TwiliGlobalEventsListener> listenersEvent =
			new ListenerSet<>(TwiliGlobalEventsListener.class);
	
	private ITwibDeviceInterface device;
	private List<TwiliDebugProcess> debugProcesses = new ArrayList<TwiliDebugProcess>();
	
	public TwiliDebugger(ITwibDeviceInterface device) {
		this.device = device;
	}

	public void addEventsListener(TwiliGlobalEventsListener listener) {
		listenersEvent.add(listener);
	}

	public void removeEventsListener(TwiliGlobalEventsListener listener) {
		listenersEvent.remove(listener);
	}
	
	public CompletableFuture<TwiliDebugProcess> attach(long pid) {
		return device.openActiveDebugger(pid).thenApply(itd -> {
			TwiliDebugProcess tdp = new TwiliDebugProcess(itd, pid);
			debugProcesses.add(tdp);
			listenersEvent.fire.processAttached(tdp);
			
			return tdp;
		});
	}

	public ITwibDeviceInterface getDevice() {
		return device;
	}

	public List<TwiliDebugProcess> getProcesses() {
		return debugProcesses;
	}

	public CompletableFuture<List<ProcessListEntry>> listAvailableProcesses() {
		return device.listProcesses();
	}

	public String getDebuggerName() {
		return "twili";
	}
}
