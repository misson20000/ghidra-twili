package agent.twili.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.twili.debugger.TwiliDebugStackFrame;
import agent.twili.debugger.TwiliDebugThread;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetStack;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "Stack",
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class TwiliModelTargetStack extends
		DefaultTargetObject<TwiliModelTargetStackFrame, TwiliModelTargetThread> implements TargetStack {
	public static final String NAME = "Stack";

	protected final TwiliModelImpl impl;
	protected final TwiliModelTargetProcess process;
	protected final TwiliDebugThread thread;

	protected final Map<Integer, TwiliModelTargetStackFrame> framesByLevel = new WeakValueHashMap<>();

	public TwiliModelTargetStack(TwiliModelTargetThread thread, TwiliModelTargetProcess process) {
		super(thread.impl, thread, NAME, "Stack");
		this.impl = thread.impl;
		this.process = process;
		this.thread = thread.thread;
		
		this.requestElements(false);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return thread.walkStack().thenAccept(stack -> {
			List<TwiliModelTargetStackFrame> frames;
			synchronized (this) {
				frames = stack.stream().map(this::getTargetFrame).collect(Collectors.toList());
			}
			setElements(frames, "Refreshed");
		});
	}
	
	private TwiliModelTargetStackFrame getTargetFrame(TwiliDebugStackFrame frame) {
		return framesByLevel.compute(frame.level, (k, v) -> {
			if(v == null) {
				return new TwiliModelTargetStackFrame(this, parent, process, frame);
			}
			
			v.updateFrom(frame);
			return v;
		});
	}
}
