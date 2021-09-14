package agent.twili.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.twili.debugger.TwiliDebugProcess;
import agent.twili.debugger.TwiliProcessEventsListener;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetAggregate;
import ghidra.dbg.target.TargetDetachable;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetKillable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.target.TargetResumable;
import ghidra.dbg.target.TargetAttacher.TargetAttachKind;
import ghidra.dbg.target.TargetAttacher.TargetAttachKindSet;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import misson20000.twili.twib.iface.horizon.DebugEventCreateProcess;

@TargetObjectSchemaInfo(
		name = "Process",
		elements = {
			@TargetElementType(type = Void.class) },
		attributes = {
			@TargetAttributeType(type = Void.class) })
public class TwiliModelTargetProcess
		extends DefaultTargetObject<TargetObject, TwiliModelTargetProcessContainer>
		implements TargetProcess, TargetAggregate, TargetExecutionStateful,
		TargetDetachable, TargetKillable, TargetResumable, TwiliProcessEventsListener {
	
	protected static final TargetAttachKindSet SUPPORTED_KINDS = TargetAttachKindSet.of( //
			TargetAttachKind.BY_OBJECT_REF, TargetAttachKind.BY_ID);
	
	protected final TwiliModelImpl impl;
	protected final TwiliDebugProcess process;

	private TargetExecutionState state;

	private String display;

	protected final TwiliModelTargetEnvironment environment;
	protected final TwiliModelTargetThreadContainer threads;
	protected final TwiliModelTargetProcessMemory memory;
	protected final TwiliModelTargetRegisterContainer registers;

	protected static String indexProcess(long pid) {
		return PathUtils.makeIndex(pid);
	}

	protected static String indexProcess(TwiliDebugProcess process) {
		return indexProcess(process.getPid());
	}

	protected static String keyProcess(TwiliDebugProcess process) {
		return PathUtils.makeKey(indexProcess(process));
	}
	
	public TwiliModelTargetProcess(TwiliModelTargetProcessContainer processes, TwiliDebugProcess process) {
		super(processes.impl, processes, keyProcess(process), "Process");
		this.impl = processes.impl;
		this.process = process;
		
		this.registers = new TwiliModelTargetRegisterContainer(this);
		this.environment = new TwiliModelTargetEnvironment(this);
		this.threads = new TwiliModelTargetThreadContainer(this);
		this.memory = new TwiliModelTargetProcessMemory(this);
		/*
		this.environment = new GdbModelTargetEnvironment(this);
		this.memory = new GdbModelTargetProcessMemory(this);
		this.modules = new GdbModelTargetModuleContainer(this);
		//this.registers = new GdbModelTargetRegisterContainer(this);
		this.threads = new GdbModelTargetThreadContainer(this);
		this.breakpoints = new GdbModelTargetBreakpointLocationContainer(this);
		*/

		process.addEventsListener(this);
		
		this.state = TargetExecutionState.STOPPED; // when we attach to a process, it stops all threads

		changeAttributes(List.of(), //
			List.of( //
				environment, //
				memory, //
				//modules, //
				registers, //
				threads //
				//breakpoints), //
				),
			Map.of( //
				STATE_ATTRIBUTE_NAME, state, //
				DISPLAY_ATTRIBUTE_NAME, updateDisplay()), //
			"Initialized");
		
		process.ingestEvents().exceptionally(ex -> {
			impl.reportError(this, "Failed to ingest process events", ex);
			return null;
		});
	}
	
	@TargetAttributeType(name = TwiliModelTargetEnvironment.NAME, required = true, fixed = true)
	public TwiliModelTargetEnvironment getEnvironment() {
		return environment;
	}
	
	@TargetAttributeType(name = TwiliModelTargetThreadContainer.NAME, required = true, fixed = true)
	public TwiliModelTargetThreadContainer getThreads() {
		return threads;
	}

	@TargetAttributeType(name = TwiliModelTargetProcessMemory.NAME, required = true, fixed = true)
	public TwiliModelTargetProcessMemory getMemory() {
		return memory;
	}
	
	@TargetAttributeType(name = TwiliModelTargetRegisterContainer.NAME, required = true, fixed = true)
	public TwiliModelTargetRegisterContainer getRegisters() {
		return registers;
	}

	/*
	@TargetAttributeType(name = GdbModelTargetModuleContainer.NAME, required = true, fixed = true)
	public GdbModelTargetModuleContainer getModules() {
		return modules;
	}
	*/

	/*
	@TargetAttributeType(name = GdbModelTargetRegisterContainer.NAME, required = true, fixed = true)
	public GdbModelTargetRegisterContainer getRegisters() {
		return registers;
	}
	*/

	/*
	@TargetAttributeType(name = GdbModelTargetThreadContainer.NAME, required = true, fixed = true)
	public GdbModelTargetThreadContainer getThreads() {
		return threads;
	}
	*/

	/*
	@TargetAttributeType(
		name = GdbModelTargetBreakpointLocationContainer.NAME,
		required = true,
		fixed = true)
	public GdbModelTargetBreakpointLocationContainer getBreakpoints() {
		return breakpoints;
	}
	*/

	private String updateDisplay() {
		StringBuilder builder = new StringBuilder();
		
		synchronized(process) {
			builder.append(String.format("0x%x", process.getPid()));
			
			builder.append(' ');
			
			if(process.hasTitleId()) {
				builder.append(String.format("%016x", process.getTitleId()));
			} else {
				builder.append("unknown title id");
			}
			
			builder.append(' ');
			
			if(process.hasProcessName()) {
				builder.append(process.getProcessName());
			} else {
				builder.append("unknown name");
			}
		}
				
		return display = builder.toString();
	}

	@Override
	public String getDisplay() {
		return display;
	}

	@Override
	public TargetExecutionState getExecutionState() {
		return state;
	}

	@Override
	public CompletableFuture<Void> resume() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CompletableFuture<Void> kill() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CompletableFuture<Void> detach() {
		// TODO Auto-generated method stub
		return null;
	}
	
	@Override
	public void processCreated(DebugEventCreateProcess event) {
		changeAttributes(List.of(), Map.ofEntries(
				Map.entry(DISPLAY_ATTRIBUTE_NAME, updateDisplay())),
				"Process created");
	}
}
