package agent.twili.model;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.twili.debugger.TwiliDebugProcess;
import agent.twili.debugger.TwiliDebugThread;
import agent.twili.debugger.TwiliProcessEventsListener;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetConfigurable;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import misson20000.twili.twib.iface.horizon.DebugEventCreateThread;
import misson20000.twili.twib.iface.horizon.DebugEventExitThread;

@TargetObjectSchemaInfo(
		name = "ThreadContainer",
		attributes = {
			@TargetAttributeType(name = TargetConfigurable.BASE_ATTRIBUTE_NAME, type = Integer.class), //
			@TargetAttributeType(type = Void.class) //
		},
		canonicalContainer = true)
public class TwiliModelTargetThreadContainer
		extends DefaultTargetObject<TwiliModelTargetThread, TwiliModelTargetProcess> implements TwiliProcessEventsListener {
	public static final String NAME = "Threads";

	protected final TwiliModelImpl impl;
	protected final TwiliDebugProcess process;

	private Map<Long, TwiliModelTargetThread> threadMap = new HashMap<>();
	
	public TwiliModelTargetThreadContainer(TwiliModelTargetProcess process) {
		super(process.impl, process, NAME, "ThreadContainer");
		this.impl = process.impl;
		this.process = process.process;
		
		process.process.addEventsListener(this);
	}
	
	@Override
	public void threadCreated(DebugEventCreateThread event, TwiliDebugThread thread) {
		TwiliModelTargetThread targetThread = getOrCreateTargetThread(thread);
		changeElements(List.of(), List.of(targetThread), "Created");
		getListeners().fire.event(parent, targetThread, TargetEventType.THREAD_CREATED,
				"Thread " + thread.getThreadId() + " started", List.of(targetThread));
	}
	
	@Override
	public void threadExited(DebugEventExitThread event, TwiliDebugThread thread) {
		TwiliModelTargetThread targetThread = threadMap.remove(thread.getThreadId());
		
		getListeners().fire.event(parent, targetThread, TargetEventType.THREAD_EXITED,
				"Thread " + thread.getThreadId() + " exited", List.of(targetThread));
		
		changeElements(List.of(TwiliModelTargetThread.indexThread(thread)), List.of(), "Exited");
	}
	
	private void updateThreads() {
		List<TwiliModelTargetThread> threads;
		synchronized(this) {
			// It's important when we're doing this that we reuse old objects if they exist.
			threads = process.getThreads().stream().map(this::getOrCreateTargetThread).collect(Collectors.toList());
		}
		setElements(threads, "Refreshed");
	}
	
	private TwiliModelTargetThread getOrCreateTargetThread(TwiliDebugThread thread) {
		if(threadMap.containsKey(thread.getThreadId())) {
			return threadMap.get(thread.getThreadId());
		} else {
			TwiliModelTargetThread target = new TwiliModelTargetThread(this, parent, thread);
			threadMap.put(thread.getThreadId(), target);
			return target;
		}
	}
	
	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		updateThreads();
		return AsyncUtils.NIL;
	}
}
