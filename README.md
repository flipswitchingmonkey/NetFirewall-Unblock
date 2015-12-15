# NetFirewall-Unblock
PowerShell helper script to quickly find blocked applications and create Allow rules

## Description
The script takes history amount of event messages from the Security Event Log where Firewall rules caused packets in a certain direction to be dropped.
The blocked applications are then shown as a list for the user to select. Upon selection an Allow rule will be created if it does not yet exist, or an existing Block rule will be changed to Allow.

### Parameters
#### history
The number of event log messages from the top that are being evaluated. Defaults to 1000. Higher values take longer to evaluate.
#### direction
Evaluate only Inbound or Outbound directed messages. Defaults to Outbound.
#### checkIfExists
Does a primitive check if there is a NetFirewallApplicationFilter entry for the application in question. 
If there is then there is a good chance that a rule for this application exists and the entry will be marked with (*).
Has no immediate effect other than informational purposes.

### Example
NetFirewall-Unblock.ps1
NetFirewall-Unblock.ps1 -history 400 -direction Inbound -checkIfExists No

### Notes
You need to run this function with administrative rights to be able to modify Firewall rules.

