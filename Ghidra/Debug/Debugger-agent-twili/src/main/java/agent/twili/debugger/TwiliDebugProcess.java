package agent.twili.debugger;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.util.datastruct.ListenerSet;
import misson20000.twili.twib.iface.ITwibDebugger;
import misson20000.twili.twib.iface.horizon.DebugArchitecture;
import misson20000.twili.twib.iface.horizon.DebugEvent;
import misson20000.twili.twib.iface.horizon.DebugEventCreateProcess;
import misson20000.twili.twib.iface.horizon.DebugEventCreateThread;
import misson20000.twili.twib.iface.horizon.DebugEventException;
import misson20000.twili.twib.iface.horizon.DebugEventExitProcess;
import misson20000.twili.twib.iface.horizon.DebugEventExitThread;
import misson20000.twili.twib.iface.horizon.MemoryInfo;

public class TwiliDebugProcess {
	private ITwibDebugger debugger;
	
	private long pid;

	private boolean hasTitleId = false;
	private long titleId;
	
	private boolean hasProcessName = false;
	private String processName;
	
	private boolean hasProcessFlags = false;
	private int processFlags;
	
	private boolean isOpen = true;
	
	public enum State {
		Stopped {
			@Override
			public boolean isRunning() {
				return false;
			}
		}, Running {
			@Override
			public boolean isRunning() {
				return true;
			}
		}, Terminated {
			@Override
			public boolean isRunning() {
				return false;
			}
		};
		
		public abstract boolean isRunning();
	}
	
	private State state; // This reflects the *intended and pending* next state, which may not *actually* be the current state quite yet.
	
	private AsyncFence continueFence = new AsyncFence(); // Asynchronous tasks that need to finish before we can continue.
	
	protected final ListenerSet<TwiliProcessEventsListener> listenersEvent =
			new ListenerSet<>(TwiliProcessEventsListener.class);
	
	private final Map<Long, TwiliDebugThread> threads = new HashMap<>();
	private List<MemoryInfo> memoryInfos = new ArrayList<>();
	
	public TwiliDebugProcess(ITwibDebugger debugger, long pid) {
		this.debugger = debugger;
		this.pid = pid;
	}
	
	public void addEventsListener(TwiliProcessEventsListener listener) {
		listenersEvent.add(listener);
	}

	public void removeEventsListener(TwiliProcessEventsListener listener) {
		listenersEvent.remove(listener);
	}
	
	public long getPid() {
		return pid;
	}
	
	public boolean hasTitleId() {
		return hasTitleId;
	}
	
	public long getTitleId() {
		return titleId;
	}
	
	public boolean hasProcessName() {
		return hasProcessName;
	}
	
	public String getProcessName() {
		return processName;
	}
	
	public boolean hasProcessFlags() {
		return hasProcessFlags;
	}
	
	public int getProcessFlags() {
		return processFlags;
	}
	
	public DebugArchitecture getArchitecture() {
		if(hasProcessFlags) {
			if((processFlags & 1) != 0) {
				return DebugArchitecture.AARCH64;
			} else {
				return DebugArchitecture.AARCH32;
			}
		} else {
			return null;
		}
	}
	
	public Collection<TwiliDebugThread> getThreads() {
		return threads.values();
	}
	
	public CompletableFuture<Void> ingestEvents() {
		CompletableFuture<Void> future = AsyncUtils.loop(TypeSpec.VOID, loop -> {
			debugger.getDebugEvent().handle(loop::consume);
		}, TypeSpec.cls(DebugEvent.class), (event, loop) -> {
			if(event == null) {
				loop.exit();
			} else {
				System.out.println("got debug event: " + event.toString());
				
				switch(event.getDebugEventType()) {
				case CreateProcess:
					handleCreateProcessEvent((DebugEventCreateProcess) event);
					break;
				case CreateThread:
					handleCreateThreadEvent((DebugEventCreateThread) event);
					break;
				case ExitProcess:
					listenersEvent.fire.processExited((DebugEventExitProcess) event);
					break;
				case ExitThread:
					handleExitThreadEvent((DebugEventExitThread) event);
					break;
				case Exception:
					handleExceptionEvent((DebugEventException) event);
					break;
				}
				loop.repeat();
			}
		});
		
		// Don't continue until we've ingested all events.
		continueFence.include(future);
		
		return future;
	}
	
	public CompletableFuture<byte[]> readMemory(long addr, long size) {
		return debugger.readMemory(addr, size);
	}
	
	public CompletableFuture<Void> writeMemory(long addr, byte[] data) {
		return debugger.writeMemory(addr,  data);
	}

	private synchronized void handleCreateProcessEvent(DebugEventCreateProcess event) {
		this.titleId = event.programId;
		this.hasTitleId = true;
		
		this.processName = event.name;
		this.hasProcessName = true;
		
		this.processFlags = event.createProcessFlags;
		this.hasProcessFlags = true;
		
		listenersEvent.fire.processCreated((DebugEventCreateProcess) event);
	}
	
	private synchronized void handleCreateThreadEvent(DebugEventCreateThread event) {
		TwiliDebugThread thread = new TwiliDebugThread(this, event.threadId, event.tlsAddress);
		
		threads.put(thread.getThreadId(), thread);
		
		listenersEvent.fire.threadCreated((DebugEventCreateThread) event, thread);
	}

	private synchronized void handleExitThreadEvent(DebugEventExitThread event) {
		TwiliDebugThread thread = threads.get(event.eventThreadId);
		
		listenersEvent.fire.threadExited((DebugEventExitThread) event, thread);
		
		threads.remove(event.eventThreadId);
	}
	
	private synchronized void handleExceptionEvent(DebugEventException event) {
		listenersEvent.fire.exception((DebugEventException) event);
		//listenersEvent.
	}

	public List<MemoryInfo> getMemoryInfos() {
		return memoryInfos;
	}

	public CompletableFuture<Void> queryAllMemory() {
		CompletableFuture<Void> future = debugger.queryMemory(0).thenCompose(new QueryAllMemoryComposer(debugger)).thenAccept(newInfos -> {
			this.memoryInfos = newInfos;
			listenersEvent.fire.memoryUpdated(newInfos);
		});
		
		// Don't continue until we've ingested all events.
		continueFence.include(future);
		
		return future;
	}
	
	public static class QueryAllMemoryComposer implements Function<MemoryInfo, CompletableFuture<List<MemoryInfo>>> {
		private final ITwibDebugger debugger;
		private final List<MemoryInfo> memoryInfoList;

		public QueryAllMemoryComposer(ITwibDebugger debugger) {
			this.debugger = debugger;
			this.memoryInfoList = new ArrayList<>();
		}

		@Override
		public CompletableFuture<List<MemoryInfo>> apply(MemoryInfo info) {
			memoryInfoList.add(info);
			
			// Did we reach the end?
			if(info.addr + info.size == 0 || info.addr + info.size < info.addr) {
				return CompletableFuture.completedFuture(memoryInfoList);
			} else {
				return debugger.queryMemory(info.addr + info.size).thenCompose(this);
			}
		}

	}
	
	private void continueProcess() {
		// TODO; this is just sketching out some necessary logic
		
		// Switch to running state to forbid any activities that require the process to be stopped.
		this.state = State.Running;
		
		this.continueFence.ready().thenCompose(__ -> {
			// actually continue
			return null;
		});
		
		this.continueFence = new AsyncFence();
	}

	public ITwibDebugger getDebugger() {
		return debugger;
	}
}
