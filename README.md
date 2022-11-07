# NFC-Android

## Features
- [X] Issue tickets with constant number of rides (5).
- [X] Validate the ticket (check expiry time and remaining rides, decrement remaining rides).
- [X] The tickets are valid for a certain time (normally one day, use 2 minute for testing) from the time when they were issued.
- [X] Start the validity period only when the ticket is used for the first time.
- [X] If the tickets have expired or they have been fully used, reformat the card and issue a new ticket.
- [X] Issue additional rides (+5) to a card without erasing any still valid ticket.
- [X] Move the master-key to the Android keystore instead of in an XML file on the reader device.
- [X] 
- [ ] Implement both client and server authentication between cloud and Android App.
- [ ] Implement logging of the ticket events to cloud.
- [ ] Implement blacklisting of tickets in the cloud, so that detected forgeries can be added to the blacklist, which
is downloaded to the ticker reader. The reader device should be able to work without Internet connectivity,
but it should make use of the cloud connection when available.
- [ ] Implement master-key fetching from the cloud, and compare it to the Android keystore cached one. If any difference is found, report it to the cloud.

## Details
### Application data structure 

#### Mark block
- 4 -> application tag
- 5 -> version
- 6 -> transaction marker

#### 2 ticket blocks
- 7 -> max ride number (counter limit)
- 8 -> counter backup
- 9 -> last check-in time
- 10 -> expiration time
- 11,12,13,14,15 -> hmac
---
- 16 -> max ride number (counter limit)
- 17 -> counter backup
- 18 -> last check-in time
- 19 -> expiration time
- 20,21,22,23,24 -> hmac

#### Logs block
- 25,26,27 -> timestamp, remaining ride, type
- 28,29,30 -> timestamp, remaining ride, type
- 31,32,33 -> timestamp, remaining ride, type
- 34,35,36 -> timestamp, remaining ride, type
- 37,38,39 -> timestamp, remaining ride, type

### Write process that can ensure atomic operations
1. transaction marker=1
2. Write all the other data
3. Write the backup counter
4. Add the counter
5. transaction marker=0
