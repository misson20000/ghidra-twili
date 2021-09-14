package misson20000.twili.twib;

public class TwibResultException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 163629988541789154L;
	
	private int resultCode;

	public TwibResultException(int resultCode) {
		this.resultCode = resultCode;
	}

	public int getModule() {
		return resultCode & 0x1ff;
	}
	
	public int getDescription() {
		return resultCode >> 9;
	}
	
	public boolean isCode(int module, int description) {
		return getModule() == module && getDescription() == description;
	}
	
	public int getResultCode() {
		return resultCode;
	}
	
	@Override
	public String getMessage() {
		return String.format("Target gave result code 0x%x (%04d-%04d)", resultCode, (resultCode & 0x1ff) + 2000, resultCode >> 9);
	}

}
