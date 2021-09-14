package agent.twili.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.twili.debugger.TwiliDebugProcess;
import agent.twili.debugger.TwiliProcessEventsListener;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.program.model.address.Address;
import ghidra.util.datastruct.WeakValueTreeMap;
import misson20000.twili.twib.iface.horizon.MemoryInfo;

@TargetObjectSchemaInfo(
		name = "Memory",
		attributes = {
			@TargetAttributeType(type = Void.class) },
		canonicalContainer = true)
public class TwiliModelTargetProcessMemory
	extends DefaultTargetObject<TwiliModelTargetMemoryRegion, TwiliModelTargetProcess>
	implements TargetMemory, TwiliProcessEventsListener {
	public static final String NAME = "Memory";

	protected final TwiliModelImpl impl;
	protected final TwiliDebugProcess process;

	protected Map<Long, TwiliModelTargetMemoryRegion> regionsByStart =
			new WeakValueTreeMap<>();

	public TwiliModelTargetProcessMemory(TwiliModelTargetProcess process) {
		super(process.impl, process, NAME, "ProcessMemory");
		this.impl = process.impl;
		this.process = process.process;
		
		this.process.addEventsListener(this);
		
		this.process.queryAllMemory().exceptionally(ex -> {
			impl.reportError(this, "Failed to perform initial memory query", ex);
			return null;
		});
	}

	private void updateUsingInfos(List<MemoryInfo> infos) {
		Map<Long, TwiliModelTargetMemoryRegion> oldRegions = regionsByStart;
		regionsByStart = new WeakValueTreeMap<>();
		
		List<TwiliModelTargetMemoryRegion> regions = infos.stream().filter(info -> info.state != MemoryInfo.MemoryState.Free && info.state != MemoryInfo.MemoryState.Inaccessible).map(info -> {
			TwiliModelTargetMemoryRegion newRegion = oldRegions.compute(info.addr, (addr, oldRegion) -> {
				if(oldRegion != null && oldRegion.canUpdateFrom(info)) {
					oldRegion.updateFrom(info);
					return oldRegion;
				} else {
					return new TwiliModelTargetMemoryRegion(this, info);
				}
			});
			regionsByStart.put(info.addr, newRegion);
			return newRegion;
		}).collect(Collectors.toList());
		
		setElements(regions, "Refreshed");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		if(refresh) {
			return this.process.queryAllMemory(); // when this completes, it will call our event listener, so no need to compose on it.
		} else {
			this.updateUsingInfos(this.process.getMemoryInfos());
			return AsyncUtils.NIL;
		}
	}
	
	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length) {
		return process.readMemory(address.getOffset(), length).thenApply(bytes -> {
			listeners.fire.memoryUpdated(this, address, bytes);
			return bytes;
		});
	}

	@Override
	public CompletableFuture<Void> writeMemory(Address address, byte[] data) {
		return process.writeMemory(address.getOffset(), data);
	}
	
	@Override
	public void memoryUpdated(List<MemoryInfo> infos) {
		this.updateUsingInfos(infos);
	}
}
