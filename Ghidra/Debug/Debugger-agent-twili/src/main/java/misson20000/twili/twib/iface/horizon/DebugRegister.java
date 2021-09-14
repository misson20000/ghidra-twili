package misson20000.twili.twib.iface.horizon;

import java.util.ArrayList;
import java.util.List;

public class DebugRegister {
	private final String name;
	private final int offset;
	private final int width;
	
	public DebugRegister(String name, int offset, int width) {
		this.name = name;
		this.offset = offset;
		this.width = width;
	}

	public static List<DebugRegister> createForAArch32() {
		List<DebugRegister> registers = new ArrayList<>();
		
		// TODO
		
		return registers;
	}
	
	public static List<DebugRegister> createForAArch64() {
		List<DebugRegister> registers = new ArrayList<>();
		
		for(int i = 0; i < 31; i++) {
			registers.add(new DebugRegister("x" + i, i * 8, 8));
		}
		
		for(int i = 0; i < 31; i++) {
			//TODO: is this helpful?
			//registers.add(new DebugRegister("w" + i, i * 8, 4));
		}
		
		registers.add(new DebugRegister("fp", 29 * 8, 8));
		registers.add(new DebugRegister("lr", 29 * 8, 8));

		registers.add(new DebugRegister("sp", 31 * 8, 8));
		registers.add(new DebugRegister("pc", 32 * 8, 8));
		registers.add(new DebugRegister("pstate", 33 * 8, 4));
		
		for(int i = 0; i < 32; i++) {
			registers.add(new DebugRegister("v" + i, 272 + i * 16, 16));
		}
		
		registers.add(new DebugRegister("fpcr", 784, 4));
		registers.add(new DebugRegister("fpsr", 788, 4));
		registers.add(new DebugRegister("tpidr", 792, 8));
		
		return registers;
	}
	
	public String getName() {
		return name;
	}

	public int getOffset() {
		return offset;
	}

	public int getByteWidth() {
		return width;
	}
}
