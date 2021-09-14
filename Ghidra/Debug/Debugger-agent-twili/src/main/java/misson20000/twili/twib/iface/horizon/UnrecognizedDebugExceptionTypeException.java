package misson20000.twili.twib.iface.horizon;

public class UnrecognizedDebugExceptionTypeException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = -3200705119022849039L;
	
	public final int type;
	
	public UnrecognizedDebugExceptionTypeException(int type) {
		super("Unrecognized debug exception type: " + type);
		
		this.type = type;
	}
}
