package agent.twili.model;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.stream.Collectors;

import agent.twili.debugger.TwiliDebugProcess;
import agent.twili.debugger.TwiliDebugThread;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.dbg.target.TargetSteppable;
import ghidra.dbg.target.TargetThread;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import misson20000.twili.twib.iface.horizon.DebugRegister;

@TargetObjectSchemaInfo(
		name = "Thread",
		elements = {
			@TargetElementType(type = Void.class) },
		attributes = {
			@TargetAttributeType(type = Void.class) })
public class TwiliModelTargetThread
		extends DefaultTargetObject<TargetObject, TwiliModelTargetThreadContainer> implements
		TargetThread, TargetExecutionStateful, TargetSteppable, TargetRegisterBank {
	
	protected static final TargetStepKindSet SUPPORTED_KINDS = TargetStepKindSet.of( //
		TargetStepKind.INTO);

	protected static String indexThread(long threadId) {
		return PathUtils.makeIndex(threadId);
	}

	protected static String indexThread(TwiliDebugThread thread) {
		return indexThread(thread.getThreadId());
	}

	protected static String keyThread(TwiliDebugThread thread) {
		return PathUtils.makeKey(indexThread(thread));
	}

	protected final TwiliModelImpl impl;
	protected final TwiliDebugProcess process;
	protected final TwiliDebugThread thread;
	
	protected String display;
	protected String shortDisplay;
	
	private Map<String, byte[]> registerCache;
	private CompletableFuture<Map<String, byte[]>> registerCacheFuture;
	
	private TwiliModelTargetStack stack;
	
	public TwiliModelTargetThread(TwiliModelTargetThreadContainer threads,
			TwiliModelTargetProcess process, TwiliDebugThread thread) {
		super(threads.impl, threads, keyThread(thread), "Thread");
		this.impl = threads.impl;
		this.process = process.process;
		this.thread = thread;

		this.stack = new TwiliModelTargetStack(this, process);

		changeAttributes(List.of(), List.of(stack), Map.of( //
			STATE_ATTRIBUTE_NAME, TargetExecutionState.STOPPED, //
			SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS, //
			SHORT_DISPLAY_ATTRIBUTE_NAME, shortDisplay = computeShortDisplay(), //
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(), //
			DESCRIPTIONS_ATTRIBUTE_NAME, getDescriptions() //
		), "Initialized");
	}
	
	private String computeDisplay() {
		return String.format("Thread 0x%x", thread.getThreadId());
	}

	private String computeShortDisplay() {
		return String.format("Thread 0x%x", thread.getThreadId());
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		return null;
	}

	@Override
	public TargetRegisterContainer getDescriptions() {
		return parent.getParent().registers;
	}
	
	@TargetAttributeType(name = TwiliModelTargetStack.NAME, required = true, fixed = true)
	public TwiliModelTargetStack getStack() {
		return stack;
	}
	
	private CompletableFuture<Map<String, byte[]>> fetchRegisters() {
		return this.registerCacheFuture = this.thread.getRegisters().thenApply(regs -> {
			this.registerCache = this.process.getArchitecture().getRegisters().stream().collect(Collectors.toMap(DebugRegister::getName, reg -> {
				byte[] bytes = new byte[reg.getByteWidth()];
				
				// Ghidra expects registers in big endian byte order, so need to flip them around.
				int offset = reg.getOffset();
				int width = reg.getByteWidth();
				for(int i = 0; i < reg.getByteWidth(); i++) {
					bytes[i] = regs[offset + width - 1 - i];
				}
				
				return bytes;
			}));
			
			listeners.fire.registersUpdated(this, this.registerCache);
			
			return this.registerCache;
		});
	}
	
	private synchronized CompletableFuture<Map<String, byte[]>> getOrFetchRegisters() {
		if(this.registerCacheFuture == null) {
			return fetchRegisters();
		} else {
			return this.registerCacheFuture;
		}
	}

	@Override
	public CompletableFuture<Map<String, byte[]>> readRegistersNamed(Collection<String> names) {
		return getOrFetchRegisters().thenApply(cache -> {
			return names.stream().collect(Collectors.toMap(Function.identity(), name -> cache.get(name)));
		});
	}

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		return getOrFetchRegisters().thenCompose(cache -> {
			values.forEach(cache::put);
			
			byte[] context = new byte[0x320];
			
			this.process.getArchitecture().getRegisters().stream().forEach(reg -> {
				// Ghidra gives registers in big endian byte order, so need to flip them around.
				byte[] bytes = cache.get(reg.getName());
				int offset = reg.getOffset();
				int width = reg.getByteWidth();
				for(int i = 0; i < reg.getByteWidth(); i++) {
					context[i] = bytes[offset + width - 1 - i];
				}
			});
			
			return this.thread.setRegisters(context);
		});
	}
	
	@Override
	public Map<String, byte[]> getCachedRegisters() {
		return this.registerCache;
	}
	
	@Override
	public synchronized CompletableFuture<Void> invalidateCaches() {
		this.registerCache = null;
		return fetchRegisters().thenApply(__ -> null);
	}
}
