package agent.twili.model;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import misson20000.twili.twib.iface.horizon.DebugRegister;

@TargetObjectSchemaInfo(name = "RegisterDescriptor", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(type = Void.class) })
public class TwiliModelTargetRegister
		extends DefaultTargetObject<TargetObject, TwiliModelTargetRegisterContainer>
		implements TargetRegister {

	protected static String indexRegister(DebugRegister register) {
		return register.getName();
	}

	protected static String keyRegister(DebugRegister register) {
		return PathUtils.makeKey(indexRegister(register));
	}

	protected final TwiliModelImpl impl;
	protected final DebugRegister register;

	protected final int bitLength;

	public TwiliModelTargetRegister(TwiliModelTargetRegisterContainer registers, DebugRegister register) {
		super(registers.impl, registers, keyRegister(register), "Register");
		this.impl = registers.impl;
		this.register = register;

		this.bitLength = register.getByteWidth() * 8;

		changeAttributes(List.of(), Map.of( //
			CONTAINER_ATTRIBUTE_NAME, registers, //
			LENGTH_ATTRIBUTE_NAME, bitLength, //
			DISPLAY_ATTRIBUTE_NAME, getName() //
		), "Initialized");
	}

	@Override
	public int getBitLength() {
		return bitLength;
	}

	@Override
	public String getDisplay() {
		return getName();
	}

	@Override
	public TwiliModelTargetRegisterContainer getContainer() {
		return parent;
	}
}
