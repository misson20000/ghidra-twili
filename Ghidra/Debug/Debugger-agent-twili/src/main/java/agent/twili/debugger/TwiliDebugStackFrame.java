package agent.twili.debugger;

public class TwiliDebugStackFrame {
	public final int level; // starts at 1
	public final long pc;
	public final long sp;
	
	public TwiliDebugStackFrame(int level, long pc, long sp) {
		this.level = level;
		this.pc = pc;
		this.sp = sp;
	}
}