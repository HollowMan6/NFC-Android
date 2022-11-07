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
- 7 -> max ride number (counter limit), counter backup
- 8 -> last check-in time
- 9 -> expiration time
- 10 -> hmac
---
- 11 -> max ride number (counter limit), counter backup
- 12 -> last check-in time
- 13 -> expiration time
- 14 -> hmac

#### Logs block
- 15,16 -> timestamp, remaining ride, type
- 17,18 -> timestamp, remaining ride, type
- 19,20 -> timestamp, remaining ride, type

### Write process that can ensure atomic operations
1. transaction marker=1
2. Write all the other data
3. Write the backup counter
4. Add the counter
5. transaction marker=0
