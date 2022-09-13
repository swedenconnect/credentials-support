package se.swedenconnect.security.credential.container.exceptions;

/**
 * General checked exception when managing PkiCredentials in a PkiCredentialContainer.
 * This exception is a checked exception mainly because it may be thrown when managing credentials
 * where the key is stored in external source such as an HSM and where an error could be
 * recoverable, e.g. by reconnecting to the HSM and trying again.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PkiCredentialContainerException extends Exception {

  private static final long serialVersionUID = -5077131594969640553L;

  /**
   * Constructs a GeneralSecurityException with no detail message.
   */
  public PkiCredentialContainerException() {
  }

  /**
   * Constructs a GeneralSecurityException with the specified detail
   * message.
   * A detail message is a String that describes this particular
   * exception.
   *
   * @param msg the detail message.
   */
  public PkiCredentialContainerException(String msg) {
    super(msg);
  }

  /**
   * Creates a {@code GeneralSecurityException} with the specified
   * detail message and cause.
   *
   * @param message the detail message (which is saved for later retrieval
   * by the {@link #getMessage()} method).
   * @param cause the cause (which is saved for later retrieval by the
   * {@link #getCause()} method).  (A {@code null} value is permitted,
   * and indicates that the cause is nonexistent or unknown.)
   * @since 1.5
   */
  public PkiCredentialContainerException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Creates a {@code GeneralSecurityException} with the specified cause
   * and a detail message of {@code (cause==null ? null : cause.toString())}
   * (which typically contains the class and detail message of
   * {@code cause}).
   *
   * @param cause the cause (which is saved for later retrieval by the
   * {@link #getCause()} method).  (A {@code null} value is permitted,
   * and indicates that the cause is nonexistent or unknown.)
   * @since 1.5
   */
  public PkiCredentialContainerException(Throwable cause) {
    super(cause);
  }
}
