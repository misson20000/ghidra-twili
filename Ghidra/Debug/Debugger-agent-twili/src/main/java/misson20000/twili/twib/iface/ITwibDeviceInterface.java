package misson20000.twili.twib.iface;

import java.util.List;
import java.util.concurrent.CompletableFuture;

public interface ITwibDeviceInterface {
	CompletableFuture<List<ProcessListEntry>> listProcesses();
	CompletableFuture<ITwibDebugger> openActiveDebugger(long pid);
	
	public static class ProcessListEntry {
		private final long pid;
		private final int result;
		private final long titleId;
		private final String processName;

		private final int mmuFlags;

		public ProcessListEntry(long pid, int result, long titleId, String processName, int mmuFlags) {
			this.pid = pid;
			this.result = result;
			this.titleId = titleId;
			this.processName = processName;
			this.mmuFlags = mmuFlags;
		}

		public long getPid() {
			return pid;
		}
		
		public int getResult() {
			return result;
		}

		public long getTitleId() {
			return titleId;
		}
		
		public String getProcessName() {
			return processName;
		}

		public int getMmuFlags() {
			return mmuFlags;
		}
	}

}
