package agent.twili.debugger;

import java.util.List;

import misson20000.twili.twib.iface.horizon.*;

public interface TwiliProcessEventsListener {
	default void processCreated(DebugEventCreateProcess event) {
	}
	
	default void threadCreated(DebugEventCreateThread event, TwiliDebugThread thread) {
	}
	
	default void processExited(DebugEventExitProcess event) {
	}
	
	default void threadExited(DebugEventExitThread event, TwiliDebugThread thread) {
	}
	
	default void exception(DebugEventException event) {
	}
	
	default void memoryUpdated(List<MemoryInfo> infos) {
	}
	
	default void stopped() {
	}
}
