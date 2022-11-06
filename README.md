# NFC-Android

# To-do
- [ ] An online server that tracks/blocks cards
- [ ] Android app caches key, expire and auto delete after certain time, then fetch the key again from server
- [X] Each card has different secret key K = h(master_key || UID)
- [X] Give warnings when card validates too fast
- [X] **Ensure atomic operations**, rollback if any error occurs

# Data structure

- 0,1 -> serial number
- 4 -> application tag
- 5 -> version
- 6 -> transaction committed
- 7 -> max ride number
- 8 -> backup ride
- 9 -> last check-in time
- 10 -> expiration time
- 11,12,13,14,15 -> hmac
- 16 -> max ride number
- 17 -> backup ride
- 18 -> last check-in time
- 19 -> expiration time
- 20,21,22,23,24 -> hmac

## Logs
- 25,26,27 -> timestamp, remaining ride, type
- 28,29,30 -> timestamp, remaining ride, type
- 31,32,33 -> timestamp, remaining ride, type
- 34,35,36 -> timestamp, remaining ride, type
- 37,38,39 -> timestamp, remaining ride, type
- 41 -> counter

# Write process that can ensure atomic operations
- transaction marker=1
- Write all the other data
- Write the backup counter
- Add the counter
- transaction marker=0
