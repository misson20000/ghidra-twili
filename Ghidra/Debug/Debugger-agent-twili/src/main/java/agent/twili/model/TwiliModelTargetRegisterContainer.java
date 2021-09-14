package agent.twili.model;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import agent.twili.debugger.TwiliDebugProcess;
import agent.twili.debugger.TwiliProcessEventsListener;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import misson20000.twili.twib.iface.horizon.DebugArchitecture;
import misson20000.twili.twib.iface.horizon.DebugEventCreateProcess;

@TargetObjectSchemaInfo(name = "RegisterContainer", attributes = {
	@TargetAttributeType(type = Void.class) }, canonicalContainer = true)
public class TwiliModelTargetRegisterContainer
		extends DefaultTargetObject<TwiliModelTargetRegister, TwiliModelTargetProcess>
		implements TargetRegisterContainer, TwiliProcessEventsListener {
	public static final String NAME = "Registers";

	protected final TwiliModelImpl impl;
	protected final TwiliDebugProcess process;

	protected DebugArchitecture currentArchitecture;

	public TwiliModelTargetRegisterContainer(TwiliModelTargetProcess process) {
		super(process.impl, process, NAME, "RegisterContainer");
		this.impl = process.impl;
		this.process = process.process;
				
		this.process.addEventsListener(this);
		
		this.updateUsingArchitecture(this.process.getArchitecture());
	}
	
	@Override
	public void processCreated(DebugEventCreateProcess event) {
		this.updateUsingArchitecture(this.process.getArchitecture());
	}

	private synchronized void updateUsingArchitecture(DebugArchitecture arch) {
		if(arch != currentArchitecture && arch != null) {
			List<TwiliModelTargetRegister> registers = arch.getRegisters().stream().map(reg -> new TwiliModelTargetRegister(this, reg)).collect(Collectors.toList());
			setElements(registers, Map.of(), "Architecture set");
			currentArchitecture = arch;
		}
	}
}
