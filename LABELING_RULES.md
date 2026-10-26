# Labeling rules for VAULT_TRANSFER approvals

Each approval gets one label: suspicious (true) or not suspicious (false).

## Mechanical rules (labels follow automatically)
1. Label TRUE if the amount is not exactly $50,000.
2. Label TRUE if the time is between 00:00 and 05:59.
#this is because this time frame is not within the working hours
3. Label TRUE if more than 3 approvals happened in the last hour.
4. Label FALSE if none of the above apply AND the approval looks ordinary.

## Judgment rule (a human decides)
5. If none of rules 1-3 apply but something else looks wrong to a reviewer
   (for example, an unusual requester or target), label TRUE and write the
   reason in a "note" field. Otherwise label FALSE.