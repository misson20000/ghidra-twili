package agent.twili.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetAttachable;
import ghidra.dbg.target.TargetAttacher;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
		name = "Session",
		elements = {
			@TargetElementType(type = Void.class) },
		attributes = {
			@TargetAttributeType(type = Void.class) })
public class TwiliModelTargetSession extends DefaultTargetModelRoot 
	implements TargetAttacher, TargetFocusScope {
	protected static final String TWILI_PROMPT = "(twili)";
	
	protected TwiliModelImpl impl;
	
	protected final TwiliModelTargetProcessContainer processes;
	protected final TwiliModelTargetAvailableContainer available;

	public TwiliModelTargetSession(TwiliModelImpl impl, TargetObjectSchema schema) {
		super(impl, "Session", schema);
		this.impl = impl;

		this.processes = new TwiliModelTargetProcessContainer(this);
		this.available = new TwiliModelTargetAvailableContainer(this);
		//this.breakpoints = new GdbModelTargetBreakpointContainer(this);

		changeAttributes(List.of(), Map.of( //
			processes.getName(), processes, //
			available.getName(), available, //
			//breakpoints.getName(), breakpoints, //
			//ACCESSIBLE_ATTRIBUTE_NAME, accessible, //
			DISPLAY_ATTRIBUTE_NAME, "Twili Session (TODO: DEVICE ID)", //
			//TargetMethod.PARAMETERS_ATTRIBUTE_NAME, TargetCmdLineLauncher.PARAMETERS, //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, TwiliModelTargetProcess.SUPPORTED_KINDS, //
			FOCUS_ATTRIBUTE_NAME, this // Satisfy schema. Will be set to first inferior.
		), "Initialized");
	}

	@TargetAttributeType(
			name = TwiliModelTargetProcessContainer.NAME,
			required = true,
			fixed = true)
	public TwiliModelTargetProcessContainer getProcesses() {
		return processes;
	}
	
	@TargetAttributeType(
			name = TwiliModelTargetAvailableContainer.NAME,
			required = true,
			fixed = true)
	public TwiliModelTargetAvailableContainer getAvailable() {
		return available;
	}
	
	@Override
	public CompletableFuture<Void> attach(TargetAttachable attachable) {
		if(!(attachable instanceof TwiliModelTargetAttachable)) {
			return CompletableFuture.failedFuture(new Exception("provided TargetAttachable model is not mine"));
		}
		
		return attach(((TwiliModelTargetAttachable) attachable).getPid());
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		return impl.debugger.attach(pid).thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<Void> requestFocus(TargetObject obj) {
		return AsyncUtils.NIL; // don't care 
	}
}
