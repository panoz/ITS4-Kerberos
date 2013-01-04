package Kerberos;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* TicketResponse-Klasse
 */

public class TicketResponse extends Object {

	private long mySessionKey;

	private long myNonce;

	private Ticket myResponseTicket;

	// Geheimer Schl�ssel, mit dem diese Antwort (Response) (simuliert)
	// verschl�sselt ist:
	private long myResponseKey;

	private boolean isEncryptedState; // Aktueller Zustand des Objekts

	// Konstruktor
	public TicketResponse(long sessionKey, long nonce, Ticket responseTicket) {
		mySessionKey = sessionKey;
		myNonce = nonce;
		myResponseTicket = responseTicket;
		myResponseKey = -1;
		isEncryptedState = false;
	}

	public long getSessionKey() {
		if (isEncryptedState) {
			printError("Zugriff auf verschl�sselte Ticket-Response (getSessionKey)");
		}
		return mySessionKey;
	}

	public long getNonce() {
		if (isEncryptedState) {
			printError("Zugriff auf verschl�sselte Ticket-Response (getNonce)");
		}
		return myNonce;
	}

	public Ticket getResponseTicket() {
		if (isEncryptedState) {
			printError("Zugriff auf verschl�sselte Ticket-Response (getResponseTicket)");
		}
		return myResponseTicket;
	}

	public boolean encrypt(long key) {
		// TicketResponse mit dem Key verschl�sseln.
		// Falls die TicketResponse bereits verschl�sselt ist, wird false zur�ckgegeben.
		if (isEncryptedState) {
			printError("TicketResponse ist bereits verschl�sselt");
			return false;
		} else {
			myResponseKey = key;
			isEncryptedState = true;
			return true;
		}
	}

	public boolean decrypt(long key) {
		// TicketResponse mit dem Key entschl�sseln.
		// Falls der Key falsch ist oder
		// falls die TicketResponse bereits entschl�sselt ist, wird false zur�ckgegeben.
		if (!isEncryptedState) {
			printError("TicketResponse ist bereits entschl�sselt");
			return false;
		}
		if (myResponseKey != key) {
			printError("TicketResponse-Entschl�sselung mit key " + key
					+ " ist fehlgeschlagen");
			return false;
		} else {
			isEncryptedState = false;
			return true;
		}
	}

	public boolean isEncrypted() {
		// Aktuellen Zustand zur�ckgeben: 
		// verschl�sselt (true) / entschl�sselt (false)
		return isEncryptedState;
	}

	public void printError(String message) {
		System.out.println("+++++++++++++++++++");
		System.out.println("+++++++++++++++++++ Fehler +++++++++++++++++++ "
				+ message + "! TicketResponse-Key: " + myResponseKey);
		System.out.println("+++++++++++++++++++");
	}

	public void print() {
		System.out.println("********* TicketResponse *******");
		System.out.println("Session Key: " + mySessionKey);
		System.out.println("Nonce: " + myNonce);
		myResponseTicket.print();
		System.out.println("Response Key: " + myResponseKey);
		if (isEncryptedState){
			System.out.println("TicketResponse-Zustand: verschl�sselt (encrypted)!");
		} else {
			System.out.println("TicketResponse-Zustand: entschl�sselt (decrypted)!");
		}
		System.out.println();
	}

}
