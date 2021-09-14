package agent.twili.model;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import misson20000.twili.twib.iface.horizon.MemoryInfo;

@TargetObjectSchemaInfo(
		name = "MemoryRegion",
		elements = {
			@TargetElementType(type = Void.class) },
		attributes = {
			@TargetAttributeType(type = Void.class) })
public class TwiliModelTargetMemoryRegion
		extends DefaultTargetObject<TargetObject, TwiliModelTargetProcessMemory>
		implements TargetMemoryRegion {
	protected static final String MEMORY_STATE_ATTRIBUTE_NAME = "memstate";
	protected static final String MEMORY_ATTRIBUTE_ATTRIBUTE_NAME = "memattr";
	protected static final String IPC_REFCOUNT_ATTRIBUTE_NAME = "ipc_refcount";
	protected static final String DEVICE_REFCOUNT_ATTRIBUTE_NAME = "device_refcount";
	
	protected static String indexRegion(MemoryInfo region) {
		return Long.toUnsignedString(region.addr, 16);
	}

	protected static String keyRegion(MemoryInfo region) {
		return PathUtils.makeKey(indexRegion(region));
	}

	private final AddressRangeImpl range;
	private String display;
	private MemoryInfo region;
	
	public TwiliModelTargetMemoryRegion(TwiliModelTargetProcessMemory memory,
			MemoryInfo region) {
		super(memory.impl, memory, keyRegion(region), "MemoryRegion");
		
		this.region = region;
		
		try {
			Address min = memory.impl.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(region.addr);
			this.range = new AddressRangeImpl(min, region.size);
		} catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
		
		changeAttributes(List.of(), Map.of( //
			MEMORY_ATTRIBUTE_NAME, memory, //
			RANGE_ATTRIBUTE_NAME, range, //
			READABLE_ATTRIBUTE_NAME, isReadable(), //
			WRITABLE_ATTRIBUTE_NAME, isWritable(), //
			EXECUTABLE_ATTRIBUTE_NAME, isExecutable(), //
			MEMORY_STATE_ATTRIBUTE_NAME, region.state.name(),
			MEMORY_ATTRIBUTE_ATTRIBUTE_NAME, region.attribute,
			IPC_REFCOUNT_ATTRIBUTE_NAME, region.ipcRefCount,
			DEVICE_REFCOUNT_ATTRIBUTE_NAME, region.deviceRefCount,
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(region) //
		), "Initialized");
	}

	private String computeDisplay(MemoryInfo region) {
		return String.format("[0x%x-0x%x] %s", region.addr, region.addr + region.size - 1, region.state.name());
	}
	
	@Override
	public AddressRange getRange() {
		return range;
	}

	@Override
	public String getDisplay() {
		return display;
	}

	@Override
	public TwiliModelTargetProcessMemory getMemory() {
		return parent;
	}

	@Override
	public boolean isReadable() {
		return (region.permission & MemoryInfo.MEMORY_PERMISSION_READ) != 0;
	}

	@Override
	public boolean isWritable() {
		return (region.permission & MemoryInfo.MEMORY_PERMISSION_WRITE) != 0;
	}

	@Override
	public boolean isExecutable() {
		return (region.permission & MemoryInfo.MEMORY_PERMISSION_EXECUTE) != 0;
	}
	
	@TargetAttributeType(
		name = MEMORY_STATE_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = false)
	public String getMemoryState() {
		return region.state.name();
	}	
	
	@TargetAttributeType(
		name = MEMORY_ATTRIBUTE_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = false)
	public int getMemoryAttribute() {
		return region.attribute;
	}	
	
	@TargetAttributeType(
		name = IPC_REFCOUNT_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = false)
	public int getIpcRefcount() {
		return region.ipcRefCount;
	}
	
	@TargetAttributeType(
		name = DEVICE_REFCOUNT_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = false)
	public int getDeviceRefcount() {
		return region.deviceRefCount;
	}
	
	protected boolean canUpdateFrom(MemoryInfo newRegion) {
		return newRegion.addr == this.region.addr && newRegion.size == this.region.size;
	}
	
	protected void updateFrom(MemoryInfo newRegion) {
		if(!canUpdateFrom(newRegion)) {
			throw new IllegalArgumentException("new region has different range");
		}
		
		this.region = newRegion;
		
		changeAttributes(List.of(), Map.of( //
			READABLE_ATTRIBUTE_NAME, isReadable(), //
			WRITABLE_ATTRIBUTE_NAME, isWritable(), //
			EXECUTABLE_ATTRIBUTE_NAME, isExecutable(), //
			MEMORY_STATE_ATTRIBUTE_NAME, region.state.name(),
			MEMORY_ATTRIBUTE_ATTRIBUTE_NAME, region.attribute,
			IPC_REFCOUNT_ATTRIBUTE_NAME, region.ipcRefCount,
			DEVICE_REFCOUNT_ATTRIBUTE_NAME, region.deviceRefCount,
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(region) //
		), "Updated");
	}
}
