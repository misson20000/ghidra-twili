package misson20000.twili.twib.iface.horizon;

import java.util.Collection;
import com.google.common.collect.ImmutableList;

public enum DebugArchitecture {	
	AARCH32(DebugRegister.createForAArch32()) {
		@Override
		public DebugRegister getLinkRegister() {
			return getRegisterByName("r14");
		}
		
		@Override
		public DebugRegister getFramePointer() {
			return getRegisterByName("r11");
		}
	}, AARCH64(DebugRegister.createForAArch64()) {
		@Override
		public DebugRegister getLinkRegister() {
			return getRegisterByName("x30");
		}
		
		@Override
		public DebugRegister getFramePointer() {
			return getRegisterByName("x29");
		}
	};
	
	private ImmutableList<DebugRegister> registers;
	
	private DebugArchitecture(Collection<DebugRegister> registers) {
		this.registers = ImmutableList.copyOf(registers);
	}

	public ImmutableList<DebugRegister> getRegisters() {
		return registers;
	}
	
	public DebugRegister getRegisterByName(String name) {
		return registers.stream().filter(reg -> reg.getName().equals(name)).findFirst().get();

	}
	
	public DebugRegister getProgramCounter() {
		return getRegisterByName("pc");
	}
	
	public DebugRegister getStackPointer() {
		return getRegisterByName("sp");
	}
	
	public abstract DebugRegister getLinkRegister();
	public abstract DebugRegister getFramePointer();
}
