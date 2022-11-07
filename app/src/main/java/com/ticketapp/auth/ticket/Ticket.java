package com.ticketapp.auth.ticket;

import android.content.Context;
import android.content.SharedPreferences;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Ticket {

    /**
     * Default keys are stored in res/values/secrets.xml
     **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final String secretAlias = TicketActivity.outer.getString(R.string.secret_alias);
    /**
     * Data Structure
     */
    private static final int PAGE_SERIAL_NUM = 0;
    private static final int SIZE_SERIAL_NUM = 2;
    private static final int PAGE_APP_TAG = 4;
    private static final int SIZE_APP_TAG = 1;
    private static final int PAGE_VERSION = 5;
    private static final int SIZE_VERSION = 1;
    // Mark for ensuring atomic operations
    private static final int PAGE_TRANS_MARK = 6;
    private static final int SIZE_TRANS_MARK = 1;
    private static final int PAGE_MAX_RIDE_1 = 7;
    private static final int PAGE_MAX_RIDE_2 = 16;
    private static final int SIZE_MAX_RIDE = 1;
    // Backup the counter for atomic write
    private static final int PAGE_COUNTER_BK_1 = 8;
    private static final int PAGE_COUNTER_BK_2 = 17;
    private static final int SIZE_COUNTER_BK = 1;
    private static final int PAGE_CHECK_TIME_1 = 9;
    private static final int PAGE_CHECK_TIME_2 = 18;
    private static final int SIZE_CHECK_TIME = 1;
    private static final int PAGE_EXP_TIME_1 = 10;
    private static final int PAGE_EXP_TIME_2 = 19;
    private static final int SIZE_EXP_TIME = 1;
    private static final int PAGE_HMAC_1 = 11;
    private static final int PAGE_HMAC_2 = 20;
    private static final int SIZE_HMAC = 5;
    private static final int PAGE_COUNTER = 41;
    private static final int SIZE_COUNTER = 1;
    private static final int PAGE_AUTH0 = 42;
    private static final int SIZE_AUTH0 = 1;
    private static final int PAGE_AUTH1 = 43;
    private static final int SIZE_AUTH1 = 1;
    private static final int PAGE_PASSWD = 44;
    private static final int SIZE_PASSWD = 4;
    /**
     * Logging
     */
    private static final int LOG_TYPE_ISSUE = 0;
    private static final int LOG_TYPE_TOPUP = 1;
    private static final int LOG_TYPE_USE = 2;
    private static final int SIZE_LOG_TYPE = 1;
    private static final int PAGE_LOGS = 25;
    private static final int NUM_LOG = 5;
    private static final int SIZE_ONE_LOG = SIZE_CHECK_TIME + SIZE_MAX_RIDE + SIZE_LOG_TYPE;
    private static final int PAGE_NEW_LOGS = PAGE_LOGS + SIZE_ONE_LOG;
    private static final int SIZE_LOGS = SIZE_ONE_LOG * NUM_LOG;
    private static final int SIZE_NEW_LOGS = SIZE_ONE_LOG * (NUM_LOG - 1);
    /**
     * Settings
     */
    // Delays in seconds for warnings when card validates too fast
    private static final int CHECK_DELAY = 5;
    // Max counter value (based on the NFC card)
    private static final int MAX_COUNTER = 65535;
    private static final int MAX_EXPIRY = 2;
    // Max ride available in the card
    private static final int MAX_RIDE_CARD = 20;
    private static final int KEY_SIZE = 16;
    private static final String APP_TAG = "CSE4";
    private static final String VERSION = "v0.1";
    private static final int KEY_TYPE_AUTH = 0;
    private static final int KEY_TYPE_HMAC = 1;
    public static SharedPreferences sharedPref = TicketActivity.outer.getSharedPreferences(secretAlias, Context.MODE_PRIVATE);
    public static SharedPreferences.Editor storageEditor = sharedPref.edit();
    public static byte[] data = new byte[192];
    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static KeyStorage keyStorage;
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
        try {
            keyStorage = new KeyStorage(TicketActivity.outer.getString(R.string.secret_alias));
        } catch (IOException e) {
            Utilities.log("KeyStorage() initialized failed", true);
            e.printStackTrace();
        }

        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        try {
            macAlgorithm.setKey(getKey(KEY_TYPE_HMAC));
        } catch (IOException e) {
            e.printStackTrace();
            infoToShow = "Failed to get the keys";
        }

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /**
     * After validation/issuing, get information
     */
    public static String getInfoToShow() {
        return infoToShow;
    }

    private static byte[] getKey(int type) throws IOException, GeneralSecurityException {
        // TODO: Fetch the keys from server
        String authKey = "UqKrQZ!YM94@2hdJ";
        String hmacKey = "QsmaRpTnSHx77lTX";

        String key = authKey;
        String enCryptedKeyAlias = TicketActivity.outer.getString(R.string.encrypted_auth_key_alias);
        if (type == KEY_TYPE_HMAC) {
            key = hmacKey;
            enCryptedKeyAlias = TicketActivity.outer.getString(R.string.encrypted_hmac_key_alias);
        }

        String enCryptedKey = sharedPref.getString(enCryptedKeyAlias, "");
        String deCryptedKey = "";

        if (enCryptedKey.isEmpty()) {
            enCryptedKey = keyStorage.encrypt(key);
            if (enCryptedKey.isEmpty()) {
                Utilities.log("Unable to encrypt the key!", true);
                throw new IOException("Unable to encrypt the key!");
            }
            storageEditor.putString(enCryptedKeyAlias, enCryptedKey);
            storageEditor.apply();

            deCryptedKey = key;
            Utilities.log("Key from fetch", false);
        } else {
            // Has stored the value, decrypt
            deCryptedKey = keyStorage.decrypt(enCryptedKey);

            // Something must be wrong if the stored key not equals to decrypted one from the Internet
            if (deCryptedKey.isEmpty() || (!key.isEmpty() && !deCryptedKey.equals(key))) {
                Utilities.log("Unable to decrypt the key!", true);
                throw new IOException("Unable to decrypt the key!");
            }
            Utilities.log("Key from storage", false);
        }
        return deCryptedKey.getBytes();
    }

    /**
     * https://stackoverflow.com/a/7619315
     */
    private byte[] toByteArray(int value) {
        return new byte[]{(byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value};
    }

    /**
     * Packing an array of 4 bytes to an int, big endian, clean code
     */
    private int fromByteArray(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) | ((bytes[1] & 0xFF) << 16) | ((bytes[2] & 0xFF) << 8) | ((bytes[3] & 0xFF));
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

    private byte[] getCardKey(byte[] serialNum) throws GeneralSecurityException {
        byte[] key = new byte[0];

        try {
            PBEKeySpec spec = new PBEKeySpec(new String(getKey(KEY_TYPE_AUTH)).toCharArray(), serialNum, 10000, 512);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            key = new byte[KEY_SIZE];
            System.arraycopy(hash, 0, key, 0, KEY_SIZE);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            e.printStackTrace();
            Utilities.log("Error using PBKDF2WithHmacSHA1!", true);
        }
        return key;
    }

    private boolean checkHeader() {
        byte[] appTag = new byte[SIZE_APP_TAG * 4];
        byte[] version = new byte[SIZE_VERSION * 4];
        boolean res = utils.readPages(PAGE_APP_TAG, SIZE_APP_TAG, appTag, 0);
        res = res && utils.readPages(PAGE_VERSION, SIZE_VERSION, version, 0);
        if (res) {
            return new String(appTag).equals(APP_TAG) && new String(version).equals(VERSION);
        }
        return false;
    }

    private boolean setHeader() {
        byte[] appTag = APP_TAG.getBytes();
        byte[] version = VERSION.getBytes();
        boolean res = utils.writePages(appTag, 0, PAGE_APP_TAG, SIZE_APP_TAG);
        res = res && utils.writePages(version, 0, PAGE_VERSION, SIZE_VERSION);
        return res;
    }

    private int getCounter() {
        byte[] counterRead = new byte[SIZE_COUNTER * 4];
        boolean res = utils.readPages(PAGE_COUNTER, SIZE_COUNTER, counterRead, 0);
        byte[] counter = {counterRead[3], counterRead[2], counterRead[1], counterRead[0]};
        if (res) {
            return fromByteArray(counter);
        }
        return -1;
    }

    private boolean setCounter() {
        byte[] counterBytes = {1, 0, 0, 0};
        return utils.writePages(counterBytes, 0, PAGE_COUNTER, SIZE_COUNTER);
    }

    private int getTransactionMarker() {
        byte[] transactionMarker = new byte[SIZE_TRANS_MARK * 4];
        boolean res = utils.readPages(PAGE_TRANS_MARK, SIZE_TRANS_MARK, transactionMarker, 0);
        if (res) {
            return fromByteArray(transactionMarker);
        }
        return -1;
    }

    private boolean setTransactionMarker(int num) {
        byte[] numBytes = toByteArray(num);
        return utils.writePages(numBytes, 0, PAGE_TRANS_MARK, SIZE_TRANS_MARK);
    }

    /**
     * Unified method generator for reading ticket data
     */
    private int getTicketData(int block, int page1Kind, int page2Kind, int sizeKind) {
        byte[] num = new byte[sizeKind * 4];
        int page = page1Kind;
        if (block == 0) {
            page = page2Kind;
        }
        boolean res = utils.readPages(page, sizeKind, num, 0);
        if (res) {
            return fromByteArray(num);
        }
        return -1;
    }

    /**
     * Unified method generator for writing ticket data
     */
    private boolean setTicketData(int num, int block, int page1Kind, int page2Kind, int sizeKind) {
        byte[] numBytes = toByteArray(num);
        int page = page1Kind;
        if (block == 0) {
            page = page2Kind;
        }
        return utils.writePages(numBytes, 0, page, sizeKind);
    }

    private byte[] organizeHMacComputeData(byte[] serialNum, int maxRide, int backupCounter, int checkinTime, int expTime) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(serialNum);
            outputStream.write(maxRide);
            outputStream.write(backupCounter);
            outputStream.write(checkinTime);
            outputStream.write(expTime);
        } catch (IOException e) {
            e.printStackTrace();
            Utilities.log("Error generate data for HMac!", true);
        }
        return outputStream.toByteArray();
    }

    private byte[] getHMac(int block) {
        byte[] hmac = new byte[SIZE_HMAC * 4];
        int page = PAGE_HMAC_1;
        if (block == 0) {
            page = PAGE_HMAC_2;
        }
        boolean res = utils.readPages(page, SIZE_HMAC, hmac, 0);
        if (res) {
            return hmac;
        }
        return new byte[0];
    }

    private boolean setHMac(byte[] HMacData, int block) {
        byte[] hmac = macAlgorithm.generateMac(HMacData);
        int page = PAGE_HMAC_1;
        if (block == 0) {
            page = PAGE_HMAC_2;
        }
        return utils.writePages(hmac, 0, page, SIZE_HMAC);
    }

    private boolean addLog(int currentTime, int remainRide, int type) {
        byte[] log = new byte[SIZE_LOGS * 4];
        byte[] otherLog = new byte[SIZE_NEW_LOGS * 4];
        boolean res = utils.readPages(PAGE_NEW_LOGS, SIZE_NEW_LOGS, otherLog, 0);
        if (res) {
            System.arraycopy(otherLog, 0, log, 0, SIZE_NEW_LOGS * 4);
            byte[] newLog = new byte[SIZE_ONE_LOG * 4];
            System.arraycopy(toByteArray(currentTime), 0, newLog, 0, SIZE_CHECK_TIME * 4);
            System.arraycopy(toByteArray(remainRide), 0, newLog, SIZE_CHECK_TIME * 4, SIZE_MAX_RIDE * 4);
            System.arraycopy(toByteArray(type), 0, newLog, (SIZE_CHECK_TIME + SIZE_MAX_RIDE) * 4, SIZE_LOG_TYPE * 4);
            System.arraycopy(newLog, 0, log, SIZE_NEW_LOGS * 4, SIZE_ONE_LOG * 4);
            return utils.writePages(log, 0, PAGE_LOGS, SIZE_LOGS);
        }
        return false;
    }

    private int[] readTicketData(int block) throws IOException {
        int maxRide = getTicketData(block, PAGE_MAX_RIDE_1, PAGE_MAX_RIDE_2, SIZE_MAX_RIDE);
        if (maxRide == -1) {
            Utilities.log("Error reading maxRide!", true);
            throw new IOException();
        }

        int backupCount = getTicketData(block, PAGE_COUNTER_BK_1, PAGE_COUNTER_BK_2, SIZE_COUNTER_BK);
        if (backupCount == -1) {
            Utilities.log("Error reading backupCount!", true);
            throw new IOException();
        }

        int checkinTime = getTicketData(block, PAGE_CHECK_TIME_1, PAGE_CHECK_TIME_2, SIZE_CHECK_TIME);
        if (checkinTime == -1) {
            Utilities.log("Error reading check in time!", true);
            throw new IOException();
        }

        int expTime = getTicketData(block, PAGE_EXP_TIME_1, PAGE_EXP_TIME_2, SIZE_EXP_TIME);
        if (expTime == -1) {
            Utilities.log("Error reading expiry time!", true);
            throw new IOException();
        }
        return new int[]{maxRide, backupCount, checkinTime, expTime};
    }

    private boolean writeTicketData(int block, int maxRide, int backupCount, int checkinTime, int expTime, byte[] serialNum) {
        if (setTransactionMarker(1)) {
            Utilities.log("Transaction marker set to 1", false);
        } else {
            Utilities.log("Error setting transaction marker to 0", true);
            return false;
        }

        if (!setTicketData(maxRide, block, PAGE_MAX_RIDE_1, PAGE_MAX_RIDE_2, SIZE_MAX_RIDE)) {
            Utilities.log("Error writing max ride!", true);
            return false;
        }

        if (!setTicketData(checkinTime, block, PAGE_CHECK_TIME_1, PAGE_CHECK_TIME_2, SIZE_CHECK_TIME)) {
            Utilities.log("Error writing check in time!", true);
            return false;
        }

        if (!setTicketData(expTime, block, PAGE_EXP_TIME_1, PAGE_EXP_TIME_2, SIZE_EXP_TIME)) {
            Utilities.log("Error writing expiry time!", true);
            return false;
        }

        byte[] writeData = organizeHMacComputeData(serialNum, maxRide, backupCount, checkinTime, expiryTime);

        if (!setHMac(writeData, block)) {
            Utilities.log("Error writing HMAC!", true);
            return false;
        }

        // Must be the last one before commit
        if (!setTicketData(backupCount, block, PAGE_COUNTER_BK_1, PAGE_COUNTER_BK_2, SIZE_COUNTER_BK)) {
            Utilities.log("Error writing counter backup!", true);
            return false;
        }

        return true;
    }

    /**
     * Issue new tickets (ignore daysValid and uses for testing purposes)
     * (Must override the old ones by writing to both blocks)
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        // The rides that will be added for issuing a ticket
        uses = 5;
        // Valid time before expiry **in minutes**
        daysValid = MAX_EXPIRY;

        boolean res;
        boolean firstTime = false;

        isValid = false;
        infoToShow = "Communication error!";

        byte[] serialNum = getSerialNum();
        if (serialNum.length == 0) {
            Utilities.log("Error reading serial number in issue()!", true);
            return false;
        }

        // Calculate the card key
        byte[] cardKey = getCardKey(serialNum);
        if (cardKey.length == 0) {
            Utilities.log("cardKey length is 0 in issue()", true);
            return false;
        }

        // Authenticate assuming the card is blank
        if (utils.authenticate(defaultAuthenticationKey)) {
            firstTime = true;
            Utilities.log("Writing a blank card", false);
            if (!setHeader()) {
                Utilities.log("Error writing header in issue()!", true);
                return false;
            }

            if (!utils.writePages(cardKey, 0, PAGE_PASSWD, SIZE_PASSWD)) {
                Utilities.log("Error updating password in issue()!", true);
                return false;
            }
        } else {
            Utilities.log("Adding more rides to the card", false);

            if (!checkHeader()) {
                Utilities.log("Header is not valid in use()!", true);
                infoToShow = "Card not recognizable or communication error!";
                return false;
            }

            res = utils.authenticate(cardKey);
            if (!res) {
                Utilities.log("Authentication failed in issue()", true);
                infoToShow = "Authentication failed";
                return false;
            }
        }

        int cnt = getCounter();
        if (cnt == -1) {
            Utilities.log("Error reading counter in issue()!", true);
            return false;
        } else if (cnt >= MAX_COUNTER) {
            Utilities.log("Card reaches lifespan!", true);
            infoToShow = "Card reaches lifespan!\ncounter" + cnt;
            return false;
        }

        Utilities.log("Counter: " + cnt, false);

        int block = cnt % 2;
        int maxRide = uses + cnt;
        remainingUses = uses;
        int backupCount = cnt;
        int checkinTime = 0;

        /** Read data if not first time */
        if (!firstTime) {
            int[] readData;
            try {
                readData = readTicketData(block);
            } catch (IOException e) {
                return false;
            }

            maxRide = readData[0];
            backupCount = readData[1];
            checkinTime = readData[2];
            expiryTime = readData[3];

            byte[] HMacData = organizeHMacComputeData(serialNum, maxRide, backupCount, checkinTime, expiryTime);
            byte[] hmac = getHMac(block);
            if (hmac.length == 0) {
                Utilities.log("Error reading HMac in issue()!", true);
                return false;
            }

            int transactionMarker = getTransactionMarker();
            if (transactionMarker == -1) {
                Utilities.log("Error reading transaction marker in issue()", true);
                return false;
            }

            boolean hmacResult = Arrays.equals(hmac, macAlgorithm.generateMac(HMacData));
            boolean needReissue = false;
            if (transactionMarker != 0 && !hmacResult) {
                Utilities.log("Transaction marker is not 0 in issue()!", true);
                /** check the other block, if the other block is valid, then copy the
                 *  data from the other block to the current block.
                 *  If both blocks are not valid, then consider it as a new ticket.
                 */
                int[] readAnotherData;
                try {
                    readAnotherData = readTicketData((block + 1) % 2);
                } catch (IOException e) {
                    return false;
                }
                byte[] HMacAnotherData = organizeHMacComputeData(serialNum, readAnotherData[0], readAnotherData[1], readAnotherData[2], readAnotherData[3]);
                byte[] hmacAnother = getHMac((block + 1) % 2);
                if (hmacAnother.length == 0) {
                    Utilities.log("Error reading HMac when recovering in issue()!", true);
                    return false;
                }

                if (Arrays.equals(hmacAnother, macAlgorithm.generateMac(HMacAnotherData))) {
                    Utilities.log("Recovering from another block", false);
                    maxRide = readAnotherData[0];
                    backupCount = readAnotherData[1];
                    checkinTime = readAnotherData[2];
                    expiryTime = readAnotherData[3];
                    // Check if the counter has been updated or not
                    if (cnt == backupCount + 1) {
                        Utilities.log("Counter has been updated in last broken write!", false);
                        maxRide += 1;
                    }
                    backupCount = cnt;
                    if (writeTicketData(block, maxRide, backupCount, checkinTime, expiryTime, serialNum)) {
                        Utilities.log("Recover successfully", false);
                        if (setTransactionMarker(0)) {
                            Utilities.log("Transaction marker set to 0", false);
                        } else {
                            Utilities.log("Error setting transaction marker to 0", true);
                            return false;
                        }
                    } else {
                        Utilities.log("Recover failed", false);
                        return false;
                    }
                } else {
                    needReissue = true;
                    Utilities.log("Both blocks are not valid, consider it as a new ticket", false);
                }
            } else if (transactionMarker != 0 && cnt == backupCount + 1) {
                Utilities.log("Counter has been updated in last broken write!", false);
                maxRide += 1;
            } else if (!hmacResult) {
                Utilities.log("HMac is not valid in issue()!", true);
                needReissue = true;
            }

            if (needReissue) {
                firstTime = true;
                maxRide = cnt;
                backupCount = cnt;
                checkinTime = 0;
                expiryTime = 0;
            }

            if (expiryTime != 0 && expiryTime < (int) (System.currentTimeMillis() / 1000)) {
                Utilities.log("Ticket expired! Clear the remaining rides.", false);
                maxRide = cnt;
            }

            maxRide += uses;
            remainingUses = maxRide - cnt;
            if (remainingUses > MAX_RIDE_CARD) {
                Utilities.log("Trying to have " + remainingUses + " rides!", true);
                remainingUses -= uses;
                infoToShow = "You already have " + remainingUses + " rides!";
                return false;
            }
        }

        /** Write data */
        // protect the user data memory from writing
        byte[] auth0Data = {3, 0, 0, 0};
        if (!utils.writePages(auth0Data, 0, PAGE_AUTH0, SIZE_AUTH0)) {
            Utilities.log("Error protected user data in issue()!", true);
            return false;
        }
        byte[] auth1Data = {1, 0, 0, 0};
        if (!utils.writePages(auth1Data, 0, PAGE_AUTH1, SIZE_AUTH1)) {
            Utilities.log("Error set only write protected in issue()!", true);
            return false;
        }

        expiryTime = 0;

        if (!writeTicketData(block, maxRide, backupCount, checkinTime, expiryTime, serialNum)) {
            return false;
        }

        if (setTransactionMarker(0)) {
            Utilities.log("Transaction marker set to 0", false);
        } else {
            Utilities.log("Error setting transaction marker to 0", true);
            return false;
        }

        infoToShow = "Ticket updated with " + uses + " more rides! Now " + remainingUses;
        int actionType = LOG_TYPE_TOPUP;
        if (firstTime) {
            infoToShow = "Ticket issued with " + remainingUses + " rides!";
            actionType = LOG_TYPE_ISSUE;
        }

        if (!addLog((int) (System.currentTimeMillis() / 1000), remainingUses, actionType)) {
            Utilities.log("Error writing counter in issue()!", true);
            // Forget about the log if it fails
        }
        isValid = true;
        return true;
    }

    /**
     * Use ticket once
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;

        infoToShow = "Communication error!";

        if (!checkHeader()) {
            Utilities.log("Header is not valid in use()!", true);
            infoToShow = "Card not recognizable or communication error!";
            return false;
        }

        byte[] serialNum = getSerialNum();
        if (serialNum.length == 0) {
            Utilities.log("Error reading serial number in use()!", true);
            return false;
        }

        // Calculate the card key
        byte[] cardKey = getCardKey(serialNum);
        if (cardKey.length == 0) {
            Utilities.log("cardKey length is 0 in use()", true);
            infoToShow = "Failed to get card key";
            return false;
        }

        // Authenticate
        res = utils.authenticate(cardKey);
        if (!res) {
            Utilities.log("Authentication failed in use()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        int cnt = getCounter();
        if (cnt == -1) {
            Utilities.log("Error reading counter in use()!", true);
            return false;
        } else if (cnt >= MAX_COUNTER) {

            Utilities.log("Card reaches lifespan!", true);
            infoToShow = "Card reaches lifespan!\ncounter" + cnt;
            return false;
        }

        Utilities.log("Counter: " + cnt, false);

        int block = cnt % 2;

        /** Read data and check */
        int[] readData;
        try {
            readData = readTicketData(block);
        } catch (IOException e) {
            return false;
        }

        int maxRide = readData[0];
        int backupCount = readData[1];
        int checkinTime = readData[2];
        expiryTime = readData[3];

        byte[] HMacData = organizeHMacComputeData(serialNum, maxRide, backupCount, checkinTime, expiryTime);
        byte[] hmac = getHMac(block);
        if (hmac.length == 0) {
            Utilities.log("Error reading HMac in use()!", true);
            return false;
        }

        int transactionMarker = getTransactionMarker();
        if (transactionMarker == -1) {
            Utilities.log("Error reading transaction marker in use()", true);
            return false;
        }

        boolean hmacResult = Arrays.equals(hmac, macAlgorithm.generateMac(HMacData));
        if (transactionMarker != 0 && !hmacResult) {
            Utilities.log("Transaction marker is not 0 and data corrupted in use()!", true);
            /** check the other block, if the other block is valid, then copy the
             *  data from the other block to the current block.
             *  If both blocks are not valid, then block the card.
             */
            int[] readAnotherData;
            try {
                readAnotherData = readTicketData((block + 1) % 2);
            } catch (IOException e) {
                return false;
            }
            byte[] HMacAnotherData = organizeHMacComputeData(serialNum, readAnotherData[0], readAnotherData[1], readAnotherData[2], readAnotherData[3]);
            byte[] hmacAnother = getHMac((block + 1) % 2);
            if (hmacAnother.length == 0) {
                Utilities.log("Error reading HMac when recovering in use()!", true);
                return false;
            }

            if (Arrays.equals(hmacAnother, macAlgorithm.generateMac(HMacAnotherData))) {
                Utilities.log("Recovering from another block", false);
                maxRide = readAnotherData[0];
                backupCount = readAnotherData[1];
                checkinTime = readAnotherData[2];
                expiryTime = readAnotherData[3];
                // Check if the counter has been updated or not
                if (cnt == backupCount + 1) {
                    Utilities.log("Counter has been updated in last broken write!", false);
                    maxRide += 1;
                }
                backupCount = cnt;
                if (writeTicketData(block, maxRide, backupCount, checkinTime, expiryTime, serialNum)) {
                    Utilities.log("Recover successfully", false);
                    if (setTransactionMarker(0)) {
                        Utilities.log("Transaction marker set to 0", false);
                    } else {
                        Utilities.log("Error setting transaction marker to 0", true);
                        return false;
                    }
                } else {
                    Utilities.log("Recover failed", false);
                    return false;
                }
            } else {
                Utilities.log("Both blocks are not valid!", false);
                infoToShow = "Corrupted Ticket!";
                return false;
                // throw new GeneralSecurityException("Corrupted Ticket!");
            }
        } else if (!hmacResult) {
            Utilities.log("HMac is not valid in use()!", true);
            infoToShow = "Corrupted Ticket!";
            return false;
        }

        // counter should always be equal or 1 greater than backup counter
        // Or it is a corrupted card with suspicious data
        if (cnt - backupCount > 1 || cnt - backupCount < 0) {
            Utilities.log("Unreasonable backup counter!", true);
            infoToShow = "Corrupted Ticket!";
            return false;
            // throw new GeneralSecurityException("Unreasonable backup counter!");
        }

        if (maxRide - cnt > MAX_RIDE_CARD) {
            Utilities.log("Unreasonable rides available!", true);
            infoToShow = "Unreasonable available rides!\nRemaining: " + (maxRide - cnt);
            return false;
            // throw new GeneralSecurityException("Unreasonable rides available!");
        }

        // TODO: Change the expiry time to be in days
        if (expiryTime - (int) (System.currentTimeMillis() / 1000) > MAX_EXPIRY * 60) {
            Utilities.log("Unreasonable expiryTime!", true);
            infoToShow = "Unreasonable expiryTime!";
            return false;
            // throw new GeneralSecurityException("Unreasonable expiryTime!");
        } else if (expiryTime != 0 && System.currentTimeMillis() / 1000 > expiryTime) {
            Utilities.log("Ticket expired in use()!", true);
            infoToShow = "Ticket expired!";
            return false;
        }

        if (cnt >= maxRide) {
            Utilities.log("Counter is greater than maxRide in use()!", true);
            infoToShow = "Ticket used up!";
            return false;
        }

        if (checkinTime + CHECK_DELAY > System.currentTimeMillis() / 1000) {
            Utilities.log("Check in time is less than the delay in use()!", true);
            infoToShow = "Ticket used too fast!";
            return false;
            // throw new GeneralSecurityException("Ticket used too fast!");
        }

        /** Write new ticket */
        block = (block + 1) % 2;
        backupCount = cnt;
        checkinTime = (int) (System.currentTimeMillis() / 1000);
        if (expiryTime == 0) {
            // TODO: Change the expiry time to be in days
            expiryTime = checkinTime + MAX_EXPIRY * 60;
        }
        remainingUses = maxRide - cnt - 1;

        if (!writeTicketData(block, maxRide, backupCount, checkinTime, expiryTime, serialNum)) {
            return false;
        }

        // setCounter() must be the last operation
        if (!setCounter()) {
            Utilities.log("Error writing counter in use()!", true);
            return false;
        }

        if (setTransactionMarker(0)) {
            Utilities.log("Transaction marker set to 0", false);
        } else {
            Utilities.log("Error setting transaction marker to 0", true);
            return false;
        }

        if (!addLog(checkinTime, remainingUses, LOG_TYPE_USE)) {
            Utilities.log("Error writing counter in use()!", true);
            // Forget about the log if it fails
        }

        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd/MM/yyyy' 'HH:mm:ss");
        Timestamp timestamp = new Timestamp((long) expiryTime * 1000);
        infoToShow = "Remaining ride: " + remainingUses + "\nExpiry time: " + simpleDateFormat.format(timestamp);
        isValid = true;
        return true;
    }
}