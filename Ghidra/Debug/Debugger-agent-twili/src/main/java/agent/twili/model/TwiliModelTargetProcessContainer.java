package agent.twili.model;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.twili.debugger.TwiliDebugProcess;
import agent.twili.debugger.TwiliGlobalEventsListener;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "ProcessContainer",
	attributes = {
		@TargetAttributeType(type = Void.class) //
	},
	canonicalContainer = true)
public class TwiliModelTargetProcessContainer
		extends DefaultTargetObject<TwiliModelTargetProcess, TwiliModelTargetSession> implements TwiliGlobalEventsListener {
	public static final String NAME = "Processes";

	protected final TwiliModelImpl impl;
	
	private Map<Long, TwiliModelTargetProcess> processMap = new HashMap<>();

	public TwiliModelTargetProcessContainer(TwiliModelTargetSession session) {
		super(session.impl, session, NAME, "ProcessContainer");
		this.impl = session.impl;
		//this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, 10), "Initialized");

		impl.debugger.addEventsListener(this);
	}

	@Override
	public void processAttached(TwiliDebugProcess process) {
		changeElements(List.of(), List.of(getOrCreateTargetProcess(process)), "Added");
	}

	@Override
	public void processDetached(long pid) {
		changeElements(List.of(TwiliModelTargetProcess.indexProcess(pid)), List.of(), "Removed");
		processMap.remove(pid);
	}
	
	/*
	@Override
	public void inferiorAdded(GdbInferior inferior, GdbCause cause) {
		GdbModelTargetInferior inf = getTargetInferior(inferior);
		changeElements(List.of(), List.of(inf), "Added");
	}

	@Override
	public void inferiorStarted(GdbInferior inf, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		inferior.inferiorStarted(inf.getPid()).exceptionally(ex -> {
			impl.reportError(this, "Could not notify inferior started", ex);
			return null;
		});
	}

	@Override
	public void inferiorExited(GdbInferior inf, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		parent.getListeners().fire.event(parent, null, TargetEventType.PROCESS_EXITED,
			"Inferior " + inf.getId() + " exited code=" + inf.getExitCode(), List.of(inferior));
		inferior.inferiorExited(inf.getExitCode());
	}

	@Override
	public void inferiorRemoved(int inferiorId, GdbCause cause) {
		synchronized (this) {
			impl.deleteModelObject(inferiorId);
		}
		changeElements(List.of(GdbModelTargetInferior.indexInferior(inferiorId)), List.of(),
			"Removed");
	}

	@Override
	public void threadCreated(GdbThread thread, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(thread.getInferior());
		GdbModelTargetThread targetThread = inferior.threads.threadCreated(thread);
		parent.getListeners().fire.event(parent, targetThread, TargetEventType.THREAD_CREATED,
			"Thread " + thread.getId() + " started", List.of(targetThread));
	}

	@Override
	public void threadExited(int threadId, GdbInferior inf, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		GdbModelTargetThread targetThread =
			inferior.threads.getCachedElements().get(GdbModelTargetThread.indexThread(threadId));
		parent.getListeners().fire.event(parent, targetThread, TargetEventType.THREAD_EXITED,
			"Thread " + threadId + " exited", List.of(targetThread));
		inferior.threads.threadExited(threadId);
	}

	@Override
	public void libraryLoaded(GdbInferior inf, String name, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		GdbModelTargetModule module = inferior.modules.libraryLoaded(name);
		parent.getListeners().fire.event(parent, null, TargetEventType.MODULE_LOADED,
			"Library " + name + " loaded", List.of(module));
	}

	@Override
	public void libraryUnloaded(GdbInferior inf, String name, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		GdbModelTargetModule module = inferior.modules.getTargetModuleIfPresent(name);
		parent.getListeners().fire.event(parent, null, TargetEventType.MODULE_UNLOADED,
			"Library " + name + " unloaded", List.of(module));
		inferior.modules.libraryUnloaded(name);
	}

	@Override
	public void memoryChanged(GdbInferior inf, long addr, int len, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		inferior.memory.memoryChanged(addr, len);
	}

	private void updateUsingInferiors(Map<Integer, GdbInferior> byIID) {
		List<GdbModelTargetInferior> inferiors;
		synchronized (this) {
			inferiors =
				byIID.values().stream().map(this::getTargetInferior).collect(Collectors.toList());
		}
		setElements(inferiors, "Refreshed");
	}
	*/
	
	private void updateProcesses() {
		List<TwiliModelTargetProcess> processes;
		synchronized(this) {
			// It's important when we're doing this that we reuse old objects if they exist.
			processes = impl.debugger.getProcesses().stream().map(this::getOrCreateTargetProcess).collect(Collectors.toList());
		}
		setElements(processes, "Refreshed");
	}
	
	private TwiliModelTargetProcess getOrCreateTargetProcess(TwiliDebugProcess process) {
		if(processMap.containsKey(process.getPid())) {
			return processMap.get(process.getPid());
		} else {
			TwiliModelTargetProcess target = new TwiliModelTargetProcess(this, process);
			processMap.put(process.getPid(), target);
			return target;
		}
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		updateProcesses();
		return AsyncUtils.NIL;
	}

}
