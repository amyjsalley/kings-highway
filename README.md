# The King's Highway

A small, passcode-protected road trip tracker with live location, check-ins, a shared photo and video album, and push notifications.

Runs on Render (free web service and free Postgres). Settings come from environment variables:

- `DATABASE_URL`
- `FAMILY_CODE` and `AMY_CODE` (passcodes)
- `SESSION_SECRET`
- `VAPID_PUBLIC` and `VAPID_PRIVATE` (notifications)
- `TRIP_DATA` (the trip's stops, kept out of the code on purpose)
