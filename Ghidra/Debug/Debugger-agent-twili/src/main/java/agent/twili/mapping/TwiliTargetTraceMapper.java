package agent.twili.mapping;

import java.util.Collection;

import ghidra.app.plugin.core.debug.mapping.AbstractDebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.mapping.DebuggerMemoryMapper;
import ghidra.app.plugin.core.debug.mapping.DebuggerRegisterMapper;
import ghidra.app.plugin.core.debug.mapping.DefaultDebuggerMemoryMapper;
import ghidra.app.plugin.core.debug.mapping.DefaultDebuggerRegisterMapper;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.CompilerSpecNotFoundException;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;

public class TwiliTargetTraceMapper extends AbstractDebuggerTargetTraceMapper {
	public TwiliTargetTraceMapper(TargetObject target, LanguageID langID, CompilerSpecID csId,
			Collection<String> extraRegNames)
			throws LanguageNotFoundException, CompilerSpecNotFoundException {
		super(target, langID, csId, extraRegNames);
	}

	@Override
	protected DebuggerMemoryMapper createMemoryMapper(TargetMemory memory) {
		return new DefaultDebuggerMemoryMapper(language, memory.getModel());
	}

	@Override
	protected DebuggerRegisterMapper createRegisterMapper(
			TargetRegisterContainer registers) {
		return new DefaultDebuggerRegisterMapper(cSpec, registers, false);
	}
}
