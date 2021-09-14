package agent.twili.mapping;

import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOffer;
import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOpinion;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetProcess;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;

public class TwiliDebuggerMappingOpinion implements DebuggerMappingOpinion {
	//protected static final LanguageID LANG_ID_ARM_LE_V8 = new LanguageID("ARM:LE:32:v8");
	protected static final LanguageID LANG_ID_AARCH64_LE_V8A = new LanguageID("AARCH64:LE:64:v8A");
	protected static final CompilerSpecID COMP_ID_DEFAULT = new CompilerSpecID("default");

	protected static class TwiliAArch64LEHorizonOffer extends AbstractTwiliDebuggerMappingOffer {
		public TwiliAArch64LEHorizonOffer(TargetProcess process) {
			super(process, 100, "Horizon aarch64", LANG_ID_AARCH64_LE_V8A, COMP_ID_DEFAULT, Set.of());
		}
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process) {
		if (env == null) {
			return Set.of();
		}
		if (!env.getDebugger().toLowerCase().contains("twili")) {
			return Set.of();
		}
		String arch = env.getArchitecture();
		if (arch.startsWith("aarch64")) {
			return Set.of(new TwiliAArch64LEHorizonOffer(process));
		}
		else if (arch.startsWith("arm")) {
			return Set.of();
			//return Set.of(new GdbArmLELinuxOffer(process));
		}
		return Set.of();
	}
}
