package misson20000.twili.twib.iface.horizon;

public class UnrecognizedDebugEventTypeException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 7393808638372508635L;
	
	public final int type;

	public UnrecognizedDebugEventTypeException(int type) {
		super("Unrecognized debug event type: " + type);
		
		this.type = type;
	}
}
