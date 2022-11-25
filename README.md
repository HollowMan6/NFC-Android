# NFC-Android

[Back-end](../../tree/backend)

[Documentation and Slides](../../tree/demo)

[Wipe Card](../../tree/wipe)

Hide Secret:
    
```bash
./gradlew hideSecretFromPropertiesFile -PpropertiesFileName=credentials.properties
```

## Features
- [X] Issue tickets with constant number of rides (5).
- [X] Validate the ticket (check expiry time and remaining rides, decrement remaining rides).
- [X] The tickets are valid for a certain time (normally one day, use 2 minute for testing) from the time when they were issued.
- [X] Start the validity period only when the ticket is used for the first time (if initial counter value equals to the current counter value, set expiry time).
- [X] If the tickets have expired or they have been fully used, reformat the card and issue a new ticket.
- [X] Issue additional rides (+5) to a card without erasing any still valid ticket.
- [X] Move the master-key to the Android keystore instead of in an XML file on the reader device.
- [X] Implement both client and server authentication between cloud and Android App. (API master secret hides with [hidden-secrets-gradle-plugin](https://github.com/klaxit/hidden-secrets-gradle-plugin)).
- [X] Implement logging of the ticket events to cloud.
- [X] Implement blacklisting of tickets in the cloud, so that detected forgeries can be added to the blacklist, which is downloaded to the ticker reader. The reader device should be able to work without Internet connectivity, but it should make use of the cloud connection when available.
- [X] Implement master-key fetching from the cloud, and compare it to the Android keystore cached one. If any difference is found, report it to the cloud.

## Details
### Application data structure 

#### Tag block
- 4 -> application tag
- 5 -> version

#### 2 ticket blocks
- 6 -> max ride number (counter limit)
- 7 -> initial counter, expected counter
- 8 -> last check-in time
- 9 -> expiration time
- 10 -> hmac
---
- 11 -> max ride number (counter limit)
- 12 -> initial counter, expected counter
- 13 -> last check-in time
- 14 -> expiration time
- 15 -> hmac

#### Logs block
- 30,31 -> timestamp, remaining ride, type
- 32,33 -> timestamp, remaining ride, type
- 34,35 -> timestamp, remaining ride, type
- 36,37 -> timestamp, remaining ride, type
- 38,39 -> timestamp, remaining ride, type
