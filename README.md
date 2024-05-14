# kql

## Summary

```kql
CommonSecurityLog
| where DestinationIP == "<IP>"
```
Check CommonSecurityLog for dest. ip

```kql
CommonSecuityLog
| where DestinationDomainName == "<domain name>"
```
<br>
Checks CommonSecurityLog for Dest. domain name

```kql
CommonSecurityLog
| where SourceIP == "<IP>"
```
<br>
Check CommonSecurityLog for Source IP

SignInLogs
| where SigninLogs == "<IP>"
Check SigninLogs for IP address

SignInLogs
| where UserPrincipalName == "<User Email>"
Check SigninLogs for UserPrincipalName

SecurityAlert
| where AlertName contains "ti map"
| where tostirng(Entities) !contains "23.227.38."
| summarize by tostring (Entities)
Check Security Alert for AlertName containing "Ti map"
The string does not contain "<ip>"
Then summarize by entities in string format

SigninLogs
| where UserPrincipalName =~ "John.Smith@domain.com" and ResultType == "0" //and IPAddress != "<IP>"
| summarize by TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, tostring(DeviceDetail)

OfficeActivity
| where Operation == "New-InboxRule and UserId contains "<User's last name>"
| summarize by tostring(Parameters) and DeviceAction != "Blocked" and UserId contains "<User's last name>"
Check OfficeActivity for New-Inbox Rules tied to user's last name, summarize any DeviceAction that was not Blocked, show parameters in string format. Performed on compromised account.

OfficeActivity
| find "<domain>"
| summarize by tostring(Parameters)

find <ip/host/whatever>
To find a field that isn't showing, then use the field that appears

SigninLogs
| where UserDisplayName == "<Username>"
| project TimeGenerated, IPAddress, Location, LocationDetails, UserAgent, Status
Outdated default sign in logs checker

SigninLogs
| where UserPrincipalName == "John.Smith@domain.com"
| project TimeGenerated, UserDisplayName, AppDisplayName, IPAddress, Location, LocationDetails, Status, AuthenticationRequirement
Outdated default sign in logs checks #2

SigninLogs
| where UserPrincipalName == "John.Smith@domain.com"
| summarize count by <field>
| project TimeGenerated, UserDisplayName, LocationDetails_string, AppDisplayName, ResourceDisplayName, Status_string
Add to end of event logs query

SigninLogs
| where UserPrincipalName == "John.Smith@domain.com"
//| where IPAddress == "<IP>"
| summarize by TimeGenerated, UserPrincipalName, Location, tostring(Status), tostring(DeviceDetail), IPAddress, AppDisplayName, tostring(LocationDetails), AuthenticationRequirement, tostring(MfaDetail), AuthenticationDetails
MY PRIMARY SIGNINLOGS SEARCH I USE DAILY

CommonSecurityLog
| where DestinationHostName == "<domain>" //and SourceIP == "<IP>"
//| where DestinationIP == "<IP>" //and SourceIP == "<IP>"
| project TimeGenerated, DeviceAction, Activity, DestinationHostName, RequestURL, RequestContext, SourceIP, SourceUserName, SourceTranslatedAddress
MY PRIMARY COMMONSECURITYLOG SEARCH I USE DAILY

AzureActivity

DeviceInfo
| where OnboardingStatus == "Can be onboarded" and OSPlatform contains ("WindowsServer")
Simplified KQL query for looking for servers to be onboarded. Wed Theme (EDR) day specific.

Still needs fine-tuning. Something exists within defender which makes this query unusable. I need to ifugre out what this is then apply it here

DeviceInfo
| where OnboardingStatus == "Can be onboarded" and OSPlatform contains ("WindowsServer")
| where DeviceCategory contains "Endpoint"
| distinct DeviceName
Resolved the above via:
> Utilization of time
> Specifying the need for endpoints
> Utilizing distinct to minimise results

DeviceInfo
| where OnboardingStatus == "Can be onboarded" and OSPlatform contains ("WindowsServer")
| where DeviceCategory contains "Endpoint"
| distinct DeviceName, OSPlatform, OSVersionInfo, DeviceType, OnboardingStatus
More honed in results of the above
Can be utilized in Wed Theme Day

IdentityInfo
| where AccountUpn == "<user>"
| distinct AccountUpn, CreatedDateTime, JobTitle, City, Country
KQL query for fast identityinfo acquisition of user

IdentityInfo
| where AccountUpn == "<user>"
| distinct AccountUpn, IsAccountEnabled, CreatedDateTime, JobTitle, City, Country
Above but now with new and improved IsAccountEnabled

IdentityInfo
| where AccountUPN == "<user>"
| distinct AccountUPN, IsAccountEnabled, AccountCreationTime, JobTitle, City, Country
Sentinel specific

IdentityInfo
| where CreatedDateTime > ago (30d)
//| where isnotempty(AccountUpn)
//| where IsAccountEnabled != "0"
| project AccountMain = AccountUpn, IsAccountEnabled, CreatedDateTime, JobTitle, City, Country
| join (DeviceInfo
  | where Timestamp > ago(30d)
//| where LoggedOnUsers != "[]"
  | project DeviceMain = DeviceName, LoggedOnUsers, JoinType
  )
  on $left.AccountMain == $right.DeviceMain
Above but has addition of DeviceInfo to enrich the informaiton more
Broken current however, provides results but the results are blank

IdentityInfo
| where UserPrincipalName == "<user>"
| project AccountMain = AccountUpn, IsAccountEnabled, CreatedDateTime, JobTitle, City, Country
| join (DeviceInfo
  | where Timestamp > ago(30d)
  | extend UserName = parse_json(LoggedOnUsers)
  | mv-expand UserName
  | project DeviceMain = DeviceName, LoggedOnUsers, JoinType
  )
  on $left.AccountMain == $right.DeviceMain

DeviceFileEvents
| where FileName endswith ".crx"
Review files for file format: .crx (chrome web extensions)

DeviceNetworkEvents
| where Timestamp between (ago(5h) .. ago(3h))
| where DeviceName == ">device.internaldomain>" //and RemoteIP == "<IP>"

let selectedTimestamp = datetime(<time>)
search in (DeviceNetworkEvents)
Timestamp between ((selectedTimestamp - 30m) .. (selectedTimestamp + 30m))
and DeviceName == "<device>"
| sort by Timestamp desc
| extend Relevance = ifff(Timestamp == selectedTimestamp, "Selected event", ifff(Timestamp < selectedTimestamp, "Earlier event", "Later event"))
| project-reorder Relevance

let selectedTimestamp = datetime(<time>)
search in (DeviceNetworkEvents)
Timestamp between ((selectedTimestamp - 30m) .. (selectedTimestamp + 30m))
and DeviceName == "<device>"
| sort by Timestamp desc
| extend Relevance = ifff(Timestamp == selectedTimestamp, "Selected event", ifff(Timestamp < selectedTimestamp, "Earlier event", "Later event"))
| project-reorder Relevance, RemoteUrl, RemoteIP

AADServicePrincipalSigninLogs
| where IPAddress == "<IP>"
| project by TimeGenerated, ServicePrincipalName, Location, ConditionalAccessStatus, IPAddress, LocationDetails, ResultType
Useful for unusual data center login

AzureDiagnostics
| where userAgent_s == "<useragent>"
| project TimeGenerated, clientIP_s, clientIp_s, httpStatusCode_d
Check AzureDiagnostics for particular Malformed User Agent

DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName contains "<device>"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort
Useful for TI Maps, review browsing activity for particular device over 7 day period

DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP contains "<IP>"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort
Useful for TI Maps, review browsing activity for particular IP over 7 day period

DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl contains "<Url>"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort
Useful for TI Maps, review browsing activity for particular url/domain over 7 day period

AADNonInteractiveSigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "<User>"
//| where IPAddress == "<IP>"
//| where AppDisplayName == "<App>"
//| where ResultType contains "53005"
| summarize by TimeGenerated, UserPrincipalName, Location, tostring(Status), tostring(DeviceDetail), IPAddress, AppDisplayName, tostring(LocationDetails), AuthenticationRequirement, tostirng(MfaDetail), AuthenticationDetails, ResultType
Useful for failed login alerts

AzureActivity
| where Caller == "<Caller>"
| where OperationNameValue has_any ("MICROSOFT.SECURITYINSIGHTS/ALERTRULES/DELETE", "MICROSOFT.SECURITYINSIGHTS/WATCHLISTS/DELETE")
| project TimeGenerated, OperationNameValue, ResourceGroup, Caller, CallerIpAddress, Type
Useful for mass cloud resource deletion

DeviceNetworkEvents
| where RemoteUrl contains "libgen"
| summarize count() by RemoteUrl
Displays urls associated to suspicious domain - ti map related - wider search for activity related to a suspicious domain

DeviceNetworkEvents
| where DeviceName contains "<Device>"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessVersionInfoInternalFileName

Syslog
| where TimeGenerated > ago(4d)
| where SyslogMessage contains "<svc account>"
| project TimeGenerated, SyslogMessage
Useful for Multiple RDP connections made by a single system
