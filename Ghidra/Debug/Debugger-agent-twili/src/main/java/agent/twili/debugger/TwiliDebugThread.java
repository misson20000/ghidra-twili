package agent.twili.debugger;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;
import java.util.function.Function;

import misson20000.twili.twib.TwibResultException;
import misson20000.twili.twib.iface.horizon.DebugArchitecture;
import misson20000.twili.twib.iface.horizon.DebugRegister;

public class TwiliDebugThread {
	private final TwiliDebugProcess process;
	private final long threadId;
	private final long tlsAddress;
	
	public TwiliDebugThread(TwiliDebugProcess process, long threadId, long tlsAddress) {
		this.process = process;
		this.threadId = threadId;
		this.tlsAddress = tlsAddress;
	}

	public long getThreadId() {
		return threadId;
	}
	
	public long getTlsAddress() {
		return tlsAddress;
	}

	public CompletableFuture<byte[]> getRegisters() {
		return process.getDebugger().getThreadContext(threadId);
	}

	public CompletableFuture<Void> setRegisters(byte[] context) {
		return process.getDebugger().setThreadContext(threadId, context);
	}

	public CompletableFuture<List<TwiliDebugStackFrame>> walkStack() {
		return getRegisters().thenApply(StackWalker::new).thenCompose(StackWalker::begin);
	}
	
	private static long readRegister(ByteBuffer buf, DebugRegister reg) {
		switch(reg.getByteWidth()) {
		case 8:
			return buf.getLong(reg.getOffset());
		case 4:
			return buf.getInt(reg.getOffset());
		default:
			throw new UnsupportedOperationException("debug register was neither 4 nor 8 bytes long");
		}
	}
	
	public class StackWalker implements BiFunction<byte[], Throwable, CompletableFuture<List<TwiliDebugStackFrame>>> {
		private List<TwiliDebugStackFrame> frames;
		
		private long framePointer;
		
		public StackWalker(byte[] registers) {
			this.frames = new ArrayList<>();
			
			DebugArchitecture arch = process.getArchitecture();
			ByteBuffer buf = ByteBuffer.wrap(registers);
			buf.order(ByteOrder.LITTLE_ENDIAN);
			
			// Add current frame
			long pc = readRegister(buf, arch.getProgramCounter());
			long sp = readRegister(buf, arch.getStackPointer());
			this.frames.add(new TwiliDebugStackFrame(frames.size(), pc, sp));
			
			// Add parent frame
			long lr = readRegister(buf, arch.getLinkRegister());
			long fp = readRegister(buf, arch.getFramePointer());
			if(lr != 0) {
				this.frames.add(new TwiliDebugStackFrame(frames.size(), lr, fp));
			}
			
			framePointer = fp;
		}
		
		public CompletableFuture<List<TwiliDebugStackFrame>> begin() {
			if(framePointer != 0) {
				// there is no composing `handle`, so we have to do this thing instead
				return process.readMemory(framePointer, 16).handle(this).thenCompose(Function.identity());
			} else {
				return CompletableFuture.completedFuture(frames);
			}
		}

		@Override
		public CompletableFuture<List<TwiliDebugStackFrame>> apply(byte[] mem, Throwable error) {
			if(error != null) {
				if(error instanceof TwibResultException) {
					TwibResultException tre = (TwibResultException) error;
					if(tre.isCode(1, 106)) { // svc::ResultInvalidCurrentMemory
						// Hit the top of the stack; we're done!
						return CompletableFuture.completedFuture(frames);
					}
				}
				
				return CompletableFuture.failedFuture(error);
			}
			
			ByteBuffer frame = ByteBuffer.wrap(mem);
			frame.order(ByteOrder.LITTLE_ENDIAN);
			
			long fp = frame.getLong();
			long lr = frame.getLong();
			
			frames.add(new TwiliDebugStackFrame(frames.size(), fp, lr));
			
			framePointer = fp;
			
			return begin();
		}
	}
}
