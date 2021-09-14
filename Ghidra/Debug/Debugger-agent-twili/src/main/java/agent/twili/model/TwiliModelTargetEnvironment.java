package agent.twili.model;

import java.util.List;
import java.util.Map;
import agent.twili.debugger.TwiliDebugProcess;
import agent.twili.debugger.TwiliProcessEventsListener;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import misson20000.twili.twib.iface.horizon.DebugArchitecture;
import misson20000.twili.twib.iface.horizon.DebugEventCreateProcess;

@TargetObjectSchemaInfo(
		name = "Environment",
		elements = {
			@TargetElementType(type = Void.class)
		},
		attributes = {
			@TargetAttributeType(type = Void.class)
		})
public class TwiliModelTargetEnvironment
		extends DefaultTargetObject<TargetObject, TwiliModelTargetProcess>
		implements TargetEnvironment, TwiliProcessEventsListener {
		public static final String NAME = "Environment";

		public static final String VISIBLE_ARCH_ATTRIBUTE_NAME = "arch";
		public static final String VISIBLE_OS_ATTRIBUTE_NAME = "os";
		public static final String VISIBLE_ENDIAN_ATTRIBUTE_NAME = "endian";

		protected final TwiliModelImpl impl;
		protected final TwiliDebugProcess process;

		protected String arch = "(unknown)";
		protected String os = "Horizon";
		protected String endian = "little";

		public TwiliModelTargetEnvironment(TwiliModelTargetProcess process) {
			super(process.impl, process, NAME, "Environment");
			this.impl = process.impl;
			this.process = process.process;
			
			this.arch = this.updateArch();

			changeAttributes(List.of(), Map.of(
				DEBUGGER_ATTRIBUTE_NAME, impl.debugger.getDebuggerName(),
				ARCH_ATTRIBUTE_NAME, arch,
				OS_ATTRIBUTE_NAME, os,
				ENDIAN_ATTRIBUTE_NAME, endian,
				VISIBLE_ARCH_ATTRIBUTE_NAME, arch,
				VISIBLE_OS_ATTRIBUTE_NAME, os,
				VISIBLE_ENDIAN_ATTRIBUTE_NAME, endian),
				"Initialized");
			
			this.process.addEventsListener(this);
		}

		@TargetAttributeType(name = VISIBLE_ARCH_ATTRIBUTE_NAME)
		public String getVisibleArch() {
			return arch;
		}

		@TargetAttributeType(name = VISIBLE_OS_ATTRIBUTE_NAME)
		public String getVisibleOs() {
			return os;
		}

		@TargetAttributeType(name = VISIBLE_ENDIAN_ATTRIBUTE_NAME)
		public String getVisibleEndian() {
			return endian;
		}

		@Override
		public String getDebugger() {
			return impl.debugger.getDebuggerName();
		}

		@Override
		public String getArchitecture() {
			return arch;
		}

		@Override
		public String getOperatingSystem() {
			return os;
		}

		@Override
		public String getEndian() {
			return endian;
		}
		
		@Override
		public void processCreated(DebugEventCreateProcess event) {
			this.arch = updateArch();
			
			changeAttributes(List.of(), Map.ofEntries(
					Map.entry(ARCH_ATTRIBUTE_NAME, arch),
					Map.entry(VISIBLE_ARCH_ATTRIBUTE_NAME, arch)),
					"Process created");
			}

		private String updateArch() {
			DebugArchitecture arch = this.process.getArchitecture();
			
			// When we've just attached to a process and haven't received the CreateProcessEvent, we don't know what architecture it is yet.
			if(arch != null) {
				switch(arch) {
				case AARCH32:
					return "arm";
				case AARCH64:
					return "aarch64";
				}
			}
			
			return "(unknown)";
		}
	}