package Kerberos;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* Client-Klasse
 */

import java.util.*;

public class Client extends Object {

	private final KDC myKDC;

	private final Server myFileserver;

	private String currentUser;

	private Ticket tgsTicket = null;

	private long tgsSessionKey; // K(C,TGS)

	private Ticket serverTicket = null;

	private long serverSessionKey; // K(C,S)

	// Konstruktor
	public Client(KDC kdc, Server server) {
		myKDC = kdc;
		myFileserver = server;
	}

	public boolean login(String userName, char[] password) {
		String tgsName = "myTGS"; // nicht schoen!
		currentUser = userName;
		TicketResponse ticketResponse = myKDC.requestTGSTicket(currentUser,
				tgsName, generateNonce());

		if (ticketResponse != null) { // TGS-Name beim KDC bekannt
			long passwd = generateSimpleKeyForPassword(password);
			if (ticketResponse.decrypt(passwd)) {
				tgsSessionKey = ticketResponse.getSessionKey();
				tgsTicket = ticketResponse.getResponseTicket();
				tgsTicket.print();
			}
		}
		// TODO : Passwort im Hauptspeicher loeschen

		return (tgsTicket != null);
	}

	public boolean showFile(String serverName, String filePath) {
		boolean success = false;
		if (tgsTicket != null) { // ohne TGS-Ticket laesst sich kein
									// Server-Ticket anfordern
			if (serverTicket == null) { // noch kein Server-Ticket vorhanden
				long currentTime = (new Date()).getTime();
				Auth tgsAuth = new Auth(currentUser, currentTime);
				tgsAuth.encrypt(tgsSessionKey);
				TicketResponse ticketResponse = myKDC.requestServerTicket(
						tgsTicket, tgsAuth, serverName, generateNonce());
				ticketResponse.print();
				if (ticketResponse.decrypt(tgsSessionKey)) {
					serverTicket = ticketResponse.getResponseTicket();
					serverSessionKey = ticketResponse.getSessionKey();
				}
			}
			if (serverTicket != null) { // immer noch kein Server-Ticket =>
										// Entschlüsselung des TicketResponse
										// fehlgeschlagen
				Auth serverAuth = new Auth(currentUser, (new Date()).getTime());
				serverAuth.encrypt(serverSessionKey);
				success = myFileserver.requestService(serverTicket, serverAuth,
						"showFile", filePath);
			}
		}
		return success;
	}

	/* *********** Hilfsmethoden **************************** */

	private long generateSimpleKeyForPassword(char[] pw) {
		// Liefert einen Schlüssel für ein Passwort zurück, hier simuliert als
		// long-Wert
		long pwKey = 0;
		for (int i = 0; i < pw.length; i++) {
			pwKey = pwKey + pw[i];
		}
		return pwKey;
	}

	private long generateNonce() {
		// Liefert einen neuen Zufallswert
		long rand = (long) (100000000 * Math.random());
		return rand;
	}
}
