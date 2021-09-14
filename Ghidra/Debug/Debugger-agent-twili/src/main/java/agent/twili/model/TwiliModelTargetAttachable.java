package agent.twili.model;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetAttachable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import misson20000.twili.twib.iface.ITwibDeviceInterface;

@TargetObjectSchemaInfo(name = "Attachable", elements = {
		@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(type = Void.class) })
public class TwiliModelTargetAttachable
	extends DefaultTargetObject<TargetObject, TwiliModelTargetAvailableContainer>
	implements TargetAttachable {

	public static final String PID_ATTRIBUTE_NAME = "pid";
	public static final String TITLE_ID_ATTRIBUTE_NAME = "titleid";
	public static final String PROCESS_NAME_ATTRIBUTE_NAME = "name";
	public static final String MMU_FLAGS_ATTRIBUTE_NAME = "mmuflags";
	
	private ITwibDeviceInterface.ProcessListEntry process;
	private String display;
	private String titleId;

	protected static String indexAttachable(ITwibDeviceInterface.ProcessListEntry process) {
		return PathUtils.makeIndex(process.getPid());
	}

	protected static String keyAttachable(ITwibDeviceInterface.ProcessListEntry process) {
		return PathUtils.makeKey(indexAttachable(process));
	}
	
	public TwiliModelTargetAttachable(TwiliModelImpl impl, TwiliModelTargetAvailableContainer parent,
			ITwibDeviceInterface.ProcessListEntry process) {
		super(impl, parent, keyAttachable(process), "Attachable");
		this.process = process;
		this.display = String.format("0x%x %016x %s", process.getPid(), process.getTitleId(), process.getProcessName());
		this.titleId = String.format("%016x", process.getTitleId());

		this.changeAttributes(List.of(), List.of(), Map.of(
			PID_ATTRIBUTE_NAME, process.getPid(),
			TITLE_ID_ATTRIBUTE_NAME, this.getTitleId(),
			PROCESS_NAME_ATTRIBUTE_NAME, this.getProcessName(),
			MMU_FLAGS_ATTRIBUTE_NAME, this.getMmuFlags(),
			DISPLAY_ATTRIBUTE_NAME, display
		), "Initialized");
	}
	
	@TargetAttributeType(name = PID_ATTRIBUTE_NAME)
	public long getPid() {
		return process.getPid();
	}
	
	@TargetAttributeType(name = TITLE_ID_ATTRIBUTE_NAME)
	public String getTitleId() {
		return this.titleId;
	}
	
	@TargetAttributeType(name = PROCESS_NAME_ATTRIBUTE_NAME)
	public String getProcessName() {
		return process.getProcessName();
	}
	
	@TargetAttributeType(name = MMU_FLAGS_ATTRIBUTE_NAME)
	public int getMmuFlags() {
		return process.getMmuFlags();
	}
}
