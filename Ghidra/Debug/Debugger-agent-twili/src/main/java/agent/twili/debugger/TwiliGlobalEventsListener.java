package agent.twili.debugger;

public interface TwiliGlobalEventsListener {
	default void processAttached(TwiliDebugProcess process) {
		
	}
	
	default void processDetached(long pid) {
		
	}
}
