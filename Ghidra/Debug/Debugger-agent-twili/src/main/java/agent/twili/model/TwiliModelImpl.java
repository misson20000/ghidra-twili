package agent.twili.model;

import agent.twili.debugger.TwiliDebugger;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.target.schema.AnnotatedSchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import misson20000.twili.twib.iface.ITwibDeviceInterface;

public class TwiliModelImpl extends AbstractDebuggerObjectModel {
	// TODO: Need some minimal memory modeling per architecture on the model/agent side.
	// The model must convert to and from Ghidra's address space names
	protected static final String SPACE_NAME = "ram";
	
	protected static final AnnotatedSchemaContext SCHEMA_CTX = new AnnotatedSchemaContext();
	protected static final TargetObjectSchema ROOT_SCHEMA =
		SCHEMA_CTX.getSchemaForClass(TwiliModelTargetSession.class);
	
	// Don't make this static, so each model has a unique "GDB" space
	protected final AddressSpace space =
		new GenericAddressSpace(SPACE_NAME, 64, AddressSpace.TYPE_RAM, 0);
	protected final AddressFactory addressFactory =
		new DefaultAddressFactory(new AddressSpace[] { space });

	protected final TwiliModelTargetSession session;
	protected final TwiliDebugger debugger;
	
	public TwiliModelImpl(ITwibDeviceInterface device) {
		this.debugger = new TwiliDebugger(device);
		this.session = new TwiliModelTargetSession(this, ROOT_SCHEMA);
		
		addModelRoot(this.session);
	}
	
	@Override
	public TargetObjectSchema getRootSchema() {
		return ROOT_SCHEMA;
	}

	@Override
	public String getBrief() {
		return "twili";
	}

	@Override
	public AddressSpace getAddressSpace(String name) {
		if (!SPACE_NAME.equals(name)) {
			return null;
		}
		return space;
	}
	
	@Override
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}
}
