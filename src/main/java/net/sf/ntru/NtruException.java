package net.sf.ntru;

public class NtruException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    NtruException(String msg) {
        super(msg);
    }
    
    NtruException(Throwable cause) {
        super(cause);
    }
}