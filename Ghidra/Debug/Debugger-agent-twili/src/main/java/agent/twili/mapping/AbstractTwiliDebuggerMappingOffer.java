package agent.twili.mapping;

import java.util.Collection;

import ghidra.app.plugin.core.debug.mapping.AbstractDebuggerMappingOffer;
import ghidra.app.plugin.core.debug.mapping.DebuggerTargetTraceMapper;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.CompilerSpecNotFoundException;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;

public class AbstractTwiliDebuggerMappingOffer extends AbstractDebuggerMappingOffer {
	public AbstractTwiliDebuggerMappingOffer(TargetObject target, int confidence,
			String description, LanguageID langID, CompilerSpecID csID,
			Collection<String> extraRegNames) {
		super(target, confidence, description, langID, csID, extraRegNames);
	}

	@Override
	public DebuggerTargetTraceMapper take() {
		try {
			return new TwiliTargetTraceMapper(target, langID, csID, extraRegNames);
		}
		catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
			throw new AssertionError(e);
		}
	}
}
