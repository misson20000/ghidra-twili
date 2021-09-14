package agent.twili.model;

import java.util.List;
import java.util.Map;
import agent.twili.debugger.TwiliDebugStackFrame;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

@TargetObjectSchemaInfo(
	name = "StackFrame",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class TwiliModelTargetStackFrame extends DefaultTargetObject<TargetObject, TwiliModelTargetStack>
		implements TargetStackFrame {
	protected static String indexFrame(TwiliDebugStackFrame frame) {
		return PathUtils.makeIndex(frame.level);
	}

	protected static String keyFrame(TwiliDebugStackFrame frame) {
		return PathUtils.makeKey(indexFrame(frame));
	}

	protected static String computeDisplay(TwiliDebugStackFrame frame) {
		return String.format("#%d 0x%x", frame.level, frame.pc);
	}

	protected final TwiliModelImpl impl;
	protected final TwiliModelTargetThread thread;
	protected final TwiliModelTargetProcess process;

	protected TwiliDebugStackFrame frame;
	protected Address pc;
	protected String display;

	public TwiliModelTargetStackFrame(TwiliModelTargetStack stack, TwiliModelTargetThread thread,
			TwiliModelTargetProcess process, TwiliDebugStackFrame frame) {
		super(stack.impl, stack, keyFrame(frame), "StackFrame");
		this.impl = stack.impl;
		this.thread = thread;
		this.process = process;
		
		this.updateFrom(frame);
	}

	@Override
	public Address getProgramCounter() {
		return pc;
	}
	
	@Override
	public String getDisplay() {
		return display;
	}

	public void updateFrom(TwiliDebugStackFrame frame) {
		this.frame = frame;
		
		this.pc = impl.getAddressFactory().getDefaultAddressSpace().getAddress(frame.pc);

		changeAttributes(List.of(), List.of(), Map.of( //
				DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(frame),
				PC_ATTRIBUTE_NAME, pc),
			"Updated");
	}
}