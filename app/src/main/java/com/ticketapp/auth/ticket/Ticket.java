package com.ticketapp.auth.ticket;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.util.Base64;

import com.example.auth.Secrets;
import com.ticketapp.auth.BuildConfig;
import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class Ticket {

    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    /**
     * Default keys are stored in res/values/secrets.xml
     **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final String secretAlias = TicketActivity.outer.getString(R.string.secret_alias);
    private static final String HOST = "https://nfc-android.fly.dev/";
    private static final String PASSWORD = new Secrets().getPassWord(BuildConfig.APPLICATION_ID);
    /**
     * Data Structure
     */
    private static final int PAGE_SERIAL_NUM = 0;
    private static final int SIZE_SERIAL_NUM = 2;
    private static final int PAGE_APP_TAG = 4;
    private static final int SIZE_APP_TAG = 1;
    private static final int PAGE_VERSION = 5;
    private static final int SIZE_VERSION = 1;
    private static final int PAGE_RIDE_1 = 6;
    private static final int PAGE_RIDE_2 = 10;
    private static final int SIZE_RIDE = 1;
    private static final int PAGE_CHECK_TIME_1 = 7;
    private static final int PAGE_CHECK_TIME_2 = 11;
    private static final int SIZE_CHECK_TIME = 1;
    private static final int PAGE_EXP_TIME_1 = 8;
    private static final int PAGE_EXP_TIME_2 = 12;
    private static final int SIZE_EXP_TIME = 1;
    private static final int PAGE_HMAC_1 = 9;
    private static final int PAGE_HMAC_2 = 13;
    private static final int SIZE_HMAC = 1;
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
    private static final int LOG_TYPE_MALICIOUS = 3;
    private static final int NUM_LOG = 3;
    private static final int SIZE_ONE_LOG = SIZE_CHECK_TIME + SIZE_RIDE;
    private static final int SIZE_LOGS = SIZE_ONE_LOG * NUM_LOG;
    private static final int PAGE_LOGS = PAGE_COUNTER - 1 - SIZE_LOGS;
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
    private static final OkHttpClient client = new OkHttpClient();
    public static SharedPreferences sharedPref = TicketActivity.outer.getSharedPreferences(secretAlias, Context.MODE_PRIVATE);
    public static SharedPreferences.Editor storageEditor = sharedPref.edit();
    public static byte[] data = new byte[192];
    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static KeyStorage keyStorage;
    private static Utilities utils;
    private static String infoToShow = "-"; // Use this to show messages
    private static String cachedLogs = "";
    private ArrayList<String> blockedSerialNum = new ArrayList<>();
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
            macAlgorithm.setKey(getKey(new byte[0], KEY_TYPE_HMAC));
        } catch (IOException e) {
            e.printStackTrace();
            infoToShow = "Failed to get the keys";
        }
        Commands ul = new Commands();
        utils = new Utilities(ul);
    }

    /**
     * After validation/issuing, get information
     */
    public static String getInfoToShow() {
        return infoToShow;
    }

    private static byte[] getKey(byte[] serialNum, int type) throws IOException, GeneralSecurityException {
        String key = "";
        String enCryptedKeyAlias = TicketActivity.outer.getString(R.string.encrypted_auth_key_alias);
        String enCryptedKeyExpTimeAlias = TicketActivity.outer.getString(R.string.encrypted_auth_key_expiration_time);
        if (type == KEY_TYPE_HMAC) {
            enCryptedKeyAlias = TicketActivity.outer.getString(R.string.encrypted_hmac_key_alias);
            enCryptedKeyExpTimeAlias = TicketActivity.outer.getString(R.string.encrypted_hmac_key_expiration_time);
        }

        String enCryptedKeyExpTime = sharedPref.getString(enCryptedKeyExpTimeAlias, "");
        long keyExpTime = 0;
        if (!enCryptedKeyExpTime.isEmpty()) {
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd/MM/yyyy' 'HH:mm:ss");
            keyExpTime = Long.parseLong(keyStorage.decrypt(enCryptedKeyExpTime));
            Timestamp timestamp = new Timestamp(keyExpTime);
            Utilities.log("Key expired time: " + simpleDateFormat.format(timestamp), false);
        }

        if (enCryptedKeyExpTime.isEmpty() || keyExpTime < System.currentTimeMillis()) {
            // Fetch the keys from cloud
            HTTPCallback cb = new HTTPCallback();
            String url = HOST + "?key=master";
            if (type == KEY_TYPE_HMAC) {
                url = HOST + "?key=hmac";
            }
            try {
                JSONObject jsonData = new JSONObject();
                jsonData.put("password", PASSWORD);
                makePost(url, jsonData.toString(), cb);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            // Allow maximum delay of 1 second
            long delayTime = System.currentTimeMillis() + 1000;
            // Wait to be available
            while (!cb.completed && System.currentTimeMillis() < delayTime) {
            }
            if (cb.completed && !cb.failed) {
                key = cb.responseStr;
            }

            if (!key.isEmpty()) {
                storageEditor.putString(enCryptedKeyExpTimeAlias, keyStorage.encrypt(Long.toString(System.currentTimeMillis() + 60 * 1000)));
                storageEditor.apply();
                Utilities.log("Key from fetch as expired", false);
            }
        }

        String enCryptedKey = sharedPref.getString(enCryptedKeyAlias, "");
        String deCryptedKey;

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
                // Cache it, will eventually report to the cloud later
                cachedLogs += Base64.encodeToString(serialNum, Base64.DEFAULT).trim() + "," + (int) (System.currentTimeMillis() / 1000) + ",0," + LOG_TYPE_MALICIOUS + "\n";
                throw new IOException("Unable to decrypt the key!");
            }
            Utilities.log("Key from storage", false);
        }
        return deCryptedKey.getBytes();
    }

    private static Call makeRequest(String url, Callback callback) {
        Request request = new Request.Builder().url(url).build();
        Call call = client.newCall(request);
        call.enqueue(callback);
        return call;
    }

    private static Call makePost(String url, String json, Callback callback) {
        RequestBody body = RequestBody.create(json, JSON);
        Request request = new Request.Builder().url(url).post(body).build();
        Call call = client.newCall(request);
        call.enqueue(callback);
        return call;
    }

    /**
     * https://stackoverflow.com/a/7619315
     */
    private byte[] toByteArray(int value) {
        return new byte[]{(byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value};
    }

    private byte[] twoToByteArray(int value1, int value2) {
        return new byte[]{(byte) (value1 >> 8), (byte) value1, (byte) (value2 >> 8), (byte) value2};
    }

    /**
     * Packing an array of 4 bytes to an int, big endian, clean code
     */
    private int fromByteArray(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) | ((bytes[1] & 0xFF) << 16) | ((bytes[2] & 0xFF) << 8) | ((bytes[3] & 0xFF));
    }

    private int[] twoFromByteArray(byte[] bytes) {
        return new int[]{((bytes[0] & 0xFF) << 8) | ((bytes[1] & 0xFF)), ((bytes[2] & 0xFF) << 8) | ((bytes[3] & 0xFF))};
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
            // Fetch the blocked list from the cloud
            Callback cb = new Callback() {
                @Override
                public void onFailure(@NonNull Call call, IOException e) {
                    e.printStackTrace();
                }

                @Override
                public void onResponse(@NonNull Call call, Response response) {
                    if (response.isSuccessful()) {
                        try {
                            String responseStr = response.body().string();
                            String[] list = responseStr.split("\n");
                            blockedSerialNum.clear();
                            blockedSerialNum = new ArrayList<>(Arrays.asList(list));
                        } catch (IOException | NullPointerException e) {
                            e.printStackTrace();
                        }
                    }
                }
            };
            makeRequest(HOST + "blocked", cb);

            if (!blockedSerialNum.contains(Base64.encodeToString(serialNum, Base64.DEFAULT).trim())) {
                return serialNum;
            } else {
                return new byte[]{0};
            }
        }
        return new byte[0];
    }

    private byte[] getCardKey(byte[] serialNum) throws GeneralSecurityException {
        byte[] key = new byte[0];

        try {
            PBEKeySpec spec = new PBEKeySpec(new String(getKey(serialNum, KEY_TYPE_AUTH)).toCharArray(), serialNum, 10000, 512);
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
     * Unified method generator for reading ticket data of two integer
     */
    private int[] getTicketDataTwo(int block, int page1Kind, int page2Kind, int sizeKind) {
        byte[] num = new byte[sizeKind * 4];
        int[] value = {-1, -1};
        int page = page1Kind;
        if (block == 0) {
            page = page2Kind;
        }
        boolean res = utils.readPages(page, sizeKind, num, 0);
        if (res) {
            value = twoFromByteArray(num);
        }
        return value;
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

    private boolean setTicketData(int num1, int num2, int block, int page1Kind, int page2Kind, int sizeKind) {
        byte[] numBytes = twoToByteArray(num1, num2);
        int page = page1Kind;
        if (block == 0) {
            page = page2Kind;
        }
        return utils.writePages(numBytes, 0, page, sizeKind);
    }

    private byte[] organizeHMacComputeData(byte[] serialNum, int maxRide, int cnt, int checkinTime, int expTime) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(serialNum);
            outputStream.write(maxRide);
            outputStream.write(cnt);
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
        byte[] hmacShorted = new byte[SIZE_HMAC * 4];
        System.arraycopy(hmac, 0, hmacShorted, 0, SIZE_HMAC * 4);
        int page = PAGE_HMAC_1;
        if (block == 0) {
            page = PAGE_HMAC_2;
        }
        return utils.writePages(hmacShorted, 0, page, SIZE_HMAC);
    }

    private boolean checkHMac(byte[] hmac, byte[] HMacData) {
        byte[] hmacCalculated = macAlgorithm.generateMac(HMacData);
        byte[] hmacShortedCalculated = new byte[SIZE_HMAC * 4];
        System.arraycopy(hmacCalculated, 0, hmacShortedCalculated, 0, SIZE_HMAC * 4);
        return Arrays.equals(hmac, hmacShortedCalculated);
    }

    private boolean commonChecks(byte[] serialNum, int cnt, int maxRide, int expectedCount, int checkinTime, int expTime, byte[] hmac, byte[] HMacData) {
        String log = Base64.encodeToString(serialNum, Base64.DEFAULT).trim() + "," + (int) (System.currentTimeMillis() / 1000) + "," + remainingUses + "," + LOG_TYPE_MALICIOUS + "\n";

        if (!checkHMac(hmac, HMacData)) {
            Utilities.log("Corrupted Ticket! Bad HMAC!", false);
            return false;
        }

        if (cnt >= MAX_COUNTER) {
            Utilities.log("Card reaches lifespan!", true);
            return false;
        }

        // counter should always be equal to the expected counter
        // Or it is a corrupted card with suspicious data
        if (cnt != expectedCount) {
            Utilities.log("Unreasonable expected counter!", true);
            // Cache it, will eventually report to the cloud later
            cachedLogs += log;
            return false;
        }

        if (maxRide - cnt > MAX_RIDE_CARD) {
            Utilities.log("Unreasonable rides available!", true);
            // Cache it, will eventually report to the cloud later
            cachedLogs += log;
            return false;
        }

        if (checkinTime - (int) (System.currentTimeMillis() / 1000) > 0) {
            Utilities.log("Unreasonable checkin time!", true);
            // Cache it, will eventually report to the cloud later
            cachedLogs += log;
            return false;
        }

        // TODO: Change the expiry time to be in days
        if (expTime - (int) (System.currentTimeMillis() / 1000) > MAX_EXPIRY * 60) {
            Utilities.log("Unreasonable expiryTime!", true);
            // Cache it, will eventually report to the cloud later
            cachedLogs += log;
            return false;
        }

        return true;
    }

    private int[] readTicketData(int block) throws IOException {
        int[] value = getTicketDataTwo(block, PAGE_RIDE_1, PAGE_RIDE_2, SIZE_RIDE);
        int maxRide = value[0];
        if (maxRide == -1) {
            Utilities.log("Error reading maxRide!", true);
            throw new IOException();
        }

        int expectedCount = value[1];
        if (expectedCount == -1) {
            Utilities.log("Error reading expectedCount!", true);
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
        return new int[]{maxRide, expectedCount, checkinTime, expTime};
    }

    private boolean writeTicketData(int block, int maxRide, int expectedCount, int checkinTime, int expTime, byte[] serialNum) {
        if (!setTicketData(maxRide, expectedCount, block, PAGE_RIDE_1, PAGE_RIDE_2, SIZE_RIDE)) {
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

        byte[] writeData = organizeHMacComputeData(serialNum, maxRide, expectedCount, checkinTime, expiryTime);

        if (!setHMac(writeData, block)) {
            Utilities.log("Error writing HMAC!", true);
            return false;
        }

        return true;
    }


    private boolean addLog(byte[] serialNum, int currentTime, int remainRide, int type) {
        cachedLogs += Base64.encodeToString(serialNum, Base64.DEFAULT).trim() + "," + currentTime + "," + remainRide + "," + type + "\n";
        // Add logs to the cloud
        try {
            JSONObject jsonData = new JSONObject();
            jsonData.put("password", PASSWORD);
            jsonData.put("cachedLog", cachedLogs);
            Callback cb = new Callback() {
                @Override
                public void onFailure(@NonNull Call call, IOException e) {
                    e.printStackTrace();
                }

                @Override
                public void onResponse(@NonNull Call call, Response response) {
                    if (response.isSuccessful()) {
                        cachedLogs = "";
                    }
                }
            };
            makePost(HOST + "logs", jsonData.toString(), cb);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        byte[] log = new byte[SIZE_LOGS * 4];
        boolean res = utils.readPages(PAGE_LOGS, SIZE_LOGS, log, 0);
        if (res) {
            int minIndex = 0;
            int minTime = (int) (System.currentTimeMillis() / 1000);
            for (int i = 0; i < NUM_LOG; i++) {
                byte[] time = new byte[SIZE_CHECK_TIME * 4];
                System.arraycopy(log, i * SIZE_ONE_LOG * 4, time, 0, SIZE_CHECK_TIME * 4);
                int seconds = fromByteArray(time);
                if (minTime > seconds) {
                    minTime = seconds;
                    minIndex = i;
                }
            }
            byte[] newLog = new byte[SIZE_ONE_LOG * 4];
            System.arraycopy(toByteArray(currentTime), 0, newLog, 0, SIZE_CHECK_TIME * 4);
            System.arraycopy(twoToByteArray(remainRide, type), 0, newLog, SIZE_CHECK_TIME * 4, SIZE_RIDE * 4);
            return utils.writePages(newLog, 0, PAGE_LOGS + minIndex * SIZE_ONE_LOG, SIZE_ONE_LOG);
        }
        return false;
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
        long timeCounter = System.currentTimeMillis();

        isValid = false;
        infoToShow = "Communication error!";

        byte[] serialNum = getSerialNum();
        if (serialNum.length == 0) {
            Utilities.log("Error reading serial number in issue()!", true);
            return false;
        } else if (serialNum.length == 1 && serialNum[0] == 0) {
            Utilities.log("Blocked card in issue()!", true);
            infoToShow = "Blocked card!";
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

            res = utils.authenticate(cardKey);
            if (!res) {
                Utilities.log("Authentication failed in issue()", true);
                infoToShow = "Authentication failed";
                return false;
            }

            if (!checkHeader()) {
                Utilities.log("Header is not valid in use()!", true);
                infoToShow = "Card not recognizable or communication error!";
                return false;
            }
        }

        int cnt = getCounter();
        if (cnt == -1) {
            Utilities.log("Error reading counter in issue()!", true);
            return false;
        }

        int block = cnt % 2;
        int maxRide = uses + cnt;
        remainingUses = uses;
        int expectedCount = cnt;
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
            expectedCount = readData[1];
            checkinTime = readData[2];
            expiryTime = readData[3];

            byte[] HMacData = organizeHMacComputeData(serialNum, maxRide, cnt, checkinTime, expiryTime);
            byte[] hmac = getHMac(block);
            if (hmac.length == 0) {
                Utilities.log("Error reading HMac in issue()!", true);
                return false;
            }

            if (!commonChecks(serialNum, cnt, maxRide, expectedCount, checkinTime, expiryTime, hmac, HMacData)) {
                infoToShow = "Corrupted Ticket!";
                return false;
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
        // protect the user data memory from reading and writing
        byte[] auth0Data = {3, 0, 0, 0};
        if (!utils.writePages(auth0Data, 0, PAGE_AUTH0, SIZE_AUTH0)) {
            Utilities.log("Error protected user data in issue()!", true);
            return false;
        }
        byte[] auth1Data = {0, 0, 0, 0};
        if (!utils.writePages(auth1Data, 0, PAGE_AUTH1, SIZE_AUTH1)) {
            Utilities.log("Error set only write protected in issue()!", true);
            return false;
        }

        expiryTime = 0;

        if (!writeTicketData(block, maxRide, expectedCount, checkinTime, expiryTime, serialNum)) {
            return false;
        }

        infoToShow = "Ticket updated with " + uses + " more rides! Now " + remainingUses;
        int actionType = LOG_TYPE_TOPUP;
        if (firstTime) {
            infoToShow = "Ticket issued with " + remainingUses + " rides!";
            actionType = LOG_TYPE_ISSUE;
        }

        if (!addLog(serialNum, (int) (System.currentTimeMillis() / 1000), remainingUses, actionType)) {
            Utilities.log("Error writing log in issue()!", true);
            // Forget about the log if it fails
        }
        isValid = true;
        infoToShow += "\nCommunication Time: " + (System.currentTimeMillis() - timeCounter) + "ms";
        return true;
    }

    /**
     * Use ticket once
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;
        long timeCounter = System.currentTimeMillis();
        infoToShow = "Communication error!";

        byte[] serialNum = getSerialNum();
        if (serialNum.length == 0) {
            Utilities.log("Error reading serial number in use()!", true);
            return false;
        } else if (serialNum.length == 1 && serialNum[0] == 0) {
            Utilities.log("Blocked card in use()!", true);
            infoToShow = "Blocked card!";
            return false;
        }

        // Calculate the card key
        byte[] cardKey = getCardKey(serialNum);
        if (cardKey.length == 0) {
            Utilities.log("cardKey length is 0 in use()", true);
            return false;
        }

        // Authenticate
        res = utils.authenticate(cardKey);
        if (!res) {
            Utilities.log("Authentication failed in use()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        if (!checkHeader()) {
            Utilities.log("Header is not valid in use()!", true);
            infoToShow = "Card not recognizable or communication error!";
            return false;
        }

        int cnt = getCounter();
        if (cnt == -1) {
            Utilities.log("Error reading counter in use()!", true);
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
        int expectedCount = readData[1];
        int checkinTime = readData[2];
        expiryTime = readData[3];

        byte[] HMacData = organizeHMacComputeData(serialNum, maxRide, cnt, checkinTime, expiryTime);
        byte[] hmac = getHMac(block);
        if (hmac.length == 0) {
            Utilities.log("Error reading HMac in use()!", true);
            return false;
        }

        if (!commonChecks(serialNum, cnt, maxRide, expectedCount, checkinTime, expiryTime, hmac, HMacData)) {
            infoToShow = "Corrupted Ticket!";
            return false;
        }

        if (expiryTime != 0 && System.currentTimeMillis() / 1000 > expiryTime) {
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
        }

        /** Write new ticket */
        block = (block + 1) % 2;
        expectedCount = cnt + 1;
        checkinTime = (int) (System.currentTimeMillis() / 1000);
        if (expiryTime == 0) {
            // TODO: Change the expiry time to be in days
            expiryTime = checkinTime + MAX_EXPIRY * 60;
        }
        remainingUses = maxRide - cnt - 1;

        if (!writeTicketData(block, maxRide, expectedCount, checkinTime, expiryTime, serialNum)) {
            return false;
        }

        // setCounter() must be the last operation
        if (!setCounter()) {
            Utilities.log("Error writing counter in use()!", true);
            return false;
        }

        if (!addLog(serialNum, checkinTime, remainingUses, LOG_TYPE_USE)) {
            Utilities.log("Error writing log in use()!", true);
            // Forget about the log if it fails
        }

        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd/MM/yyyy' 'HH:mm:ss");
        Timestamp timestamp = new Timestamp((long) expiryTime * 1000);
        infoToShow = "Remaining ride: " + remainingUses + "\nExpiry time: " + simpleDateFormat.format(timestamp) + "\nCommunication Time: " + (System.currentTimeMillis() - timeCounter) + "ms";
        isValid = true;
        return true;
    }
}

class HTTPCallback implements Callback {
    public String responseStr = "";
    public int code;
    public boolean failed = false;
    public boolean completed = false;

    @Override
    public void onFailure(@NonNull Call call, IOException e) {
        // Something went wrong
        failed = true;
        completed = true;
        e.printStackTrace();
    }

    @Override
    public void onResponse(@NonNull Call call, Response response) {
        code = response.code();
        if (response.isSuccessful()) {
            try {
                responseStr = response.body().string();
            } catch (IOException | NullPointerException e) {
                failed = true;
                completed = true;
                e.printStackTrace();
            }
        } else {
            // Request not successful
            failed = true;
        }
        completed = true;
    }
}
