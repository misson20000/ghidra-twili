package agent.twili.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.util.datastruct.WeakValueHashMap;
import misson20000.twili.twib.iface.ITwibDeviceInterface;

@TargetObjectSchemaInfo(name = "AvailableContainer", elementResync = ResyncMode.ALWAYS, attributes = {
		@TargetAttributeType(type = Void.class) //
	}, canonicalContainer = true)
public class TwiliModelTargetAvailableContainer
	extends DefaultTargetObject<TwiliModelTargetAttachable, TwiliModelTargetSession> {
	public static final String NAME = "Available";
	
	protected TwiliModelImpl impl;

	protected final Map<Long, TwiliModelTargetAttachable> attachablesById =
			new WeakValueHashMap<>();
	
	public TwiliModelTargetAvailableContainer(TwiliModelTargetSession session) {
		super(session.impl, session, NAME, "AvailableContainer");
		this.impl = session.impl;
	}
	
	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return impl.debugger.listAvailableProcesses().thenAccept(list -> {
			List<TwiliModelTargetAttachable> available;
			synchronized (this) {
				// NOTE: If more details added to entries, should clear attachablesById
				available =
					list.stream().map(this::getTargetAttachable).collect(Collectors.toList());
			}
			setElements(available, "Refreshed");
		});
	}
	
	protected synchronized TwiliModelTargetAttachable getTargetAttachable(
			ITwibDeviceInterface.ProcessListEntry process) {
		return attachablesById.computeIfAbsent(process.getPid(),
			i -> new TwiliModelTargetAttachable(impl, this, process));
	}
}
