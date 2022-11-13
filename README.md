# NFC-Android

[Back-end](../../tree/backend)

[Wipe Card](../../tree/wipe)

## Features
- [X] Issue tickets with constant number of rides (5).
- [X] Validate the ticket (check expiry time and remaining rides, decrement remaining rides).
- [X] The tickets are valid for a certain time (normally one day, use 2 minute for testing) from the time when they were issued.
- [X] Start the validity period only when the ticket is used for the first time.
- [X] If the tickets have expired or they have been fully used, reformat the card and issue a new ticket.
- [X] Issue additional rides (+5) to a card without erasing any still valid ticket.
- [X] Move the master-key to the Android keystore instead of in an XML file on the reader device.
- [X] Implement both client and server authentication between cloud and Android App.
- [X] Implement logging of the ticket events to cloud.
- [X] Implement blacklisting of tickets in the cloud, so that detected forgeries can be added to the blacklist, which is downloaded to the ticker reader. The reader device should be able to work without Internet connectivity, but it should make use of the cloud connection when available.
- [X] Implement master-key fetching from the cloud, and compare it to the Android keystore cached one. If any difference is found, report it to the cloud.

## Details
### Application data structure 

#### Tag block
- 4 -> application tag
- 5 -> version

#### 2 ticket blocks
- 6 -> max ride number (counter limit), expected counter
- 7 -> last check-in time
- 8 -> expiration time
- 9 -> hmac
---
- 10 -> max ride number (counter limit), expected counter
- 11 -> last check-in time
- 12 -> expiration time
- 13 -> hmac

#### Logs block
- 34,35 -> timestamp, remaining ride, type
- 36,37 -> timestamp, remaining ride, type
- 38,39 -> timestamp, remaining ride, type
