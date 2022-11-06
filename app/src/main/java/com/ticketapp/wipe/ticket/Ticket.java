package com.ticketapp.wipe.ticket;

import com.ticketapp.wipe.R;
import com.ticketapp.wipe.app.main.TicketActivity;
import com.ticketapp.wipe.app.ulctools.Commands;
import com.ticketapp.wipe.app.ulctools.Utilities;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You will
 * need to change the keys, design and implement functions to issue and validate tickets. Keep your
 * code readable and write clarifying comments when necessary.
 */
public class Ticket {
    /**
     * Default keys are stored in res/values/secrets.xml
     **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();

    /**
     * MUST diversify the keys.
     */
    private static final byte[] authenticationKey = TicketActivity.outer.getString(R.string.auth_key).getBytes(); // 16-byte key
    private static final byte[] hmacKey = TicketActivity.outer.getString(R.string.hmac_key).getBytes(); // 16-byte key
    private static final int PAGE_SERIAL_NUM = 0;
    private static final int SIZE_SERIAL_NUM = 2;
    private static final int SIZE_DATA = 36;
    private static final int PAGE_PASSWD = 44;
    private static final int SIZE_PASSWD = 4;
    private static final int KEY_SIZE = 16;

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;
    private static String infoToShow = "-"; // Use this to show messages
    private Boolean isValid = false;
    private int remainingUses = 0;
    private int expiryTime = 0;

    /**
     * Create a new ticket
     */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(hmacKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /**
     * After validation/issuing, get information
     */
    public static String getInfoToShow() {
        return infoToShow;
    }

    /**
     * After validation, get ticket status: was it valid or not?
     */
    public boolean isValid() {
        return isValid;
    }

    /**
     * After validation, get the number of remaining uses
     */
    public int getRemainingUses() {
        return remainingUses;
    }

    /**
     * After validation, get the expiry time
     */
    public int getExpiryTime() {
        return expiryTime;
    }

    private byte[] getSerialNum() {
        byte[] serialNum = new byte[SIZE_SERIAL_NUM * 4];
        if (utils.readPages(PAGE_SERIAL_NUM, SIZE_SERIAL_NUM, serialNum, 0)) {
            return serialNum;
        }
        return new byte[0];
    }

    private byte[] getCardKey(byte[] serialNum) {
        byte[] key = new byte[0];
        PBEKeySpec spec = new PBEKeySpec(new String(authenticationKey).toCharArray(), serialNum, 10000, 512);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            key = new byte[KEY_SIZE];
            System.arraycopy(hash, 0, key, 0, KEY_SIZE);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            Utilities.log("Error using PBKDF2WithHmacSHA1!", true);
        }
        return key;
    }

    /**
     * Issue new tickets
     * <p>
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;

        isValid = false;
        infoToShow = "Communication error!";

        byte[] serialNum = getSerialNum();
        if (serialNum.length == 0) {
            return false;
        }

        // Calculate the card key
        byte[] cardKey = getCardKey(serialNum);
        if (cardKey.length == 0) {
            return false;
        }

        // Authenticate assuming the card is blank
        if (!utils.authenticate(defaultAuthenticationKey) && !utils.authenticate(cardKey)) {
            infoToShow = "Authentication failed";
            return false;
        }

        // Format data:
        byte[] message = new byte[SIZE_DATA * 4];
        res = utils.writePages(message, 0, 4, SIZE_DATA);

        // Set information to show for the user
        if (res) {
            infoToShow = "Finished wiping card";
        } else {
            infoToShow = "Failed to write";
        }

        if (!utils.writePages(defaultAuthenticationKey, 0, PAGE_PASSWD, SIZE_PASSWD)) {
            infoToShow = "Error updating password";
            return false;
        }

        isValid = true;
        return true;
    }

    /**
     * Use ticket once
     * <p>
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;

        infoToShow = "Please use issue";
        return false;
    }
}