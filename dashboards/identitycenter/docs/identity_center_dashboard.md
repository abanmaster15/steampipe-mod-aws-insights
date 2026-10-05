This dashboard answers the following questions:

- How many IAM Identity Center users, groups and permission sets are there?
- Which users and groups have access to each account, and with which permission sets?
- Which accounts can each user access, and is that access direct or inherited from a group?
- Which groups does each user belong to?
- Which policies are attached to each permission set, and which permission sets are unassigned?

Note: Identity Center APIs are only reachable from the management (or delegated admin) account. Set the `identity_center_connection` variable to that account's Steampipe connection.
