# kql

## Summary
This README houses queries that I have utilized during my work in the field. Inspiration for this document, my upskilling and some queries goes to reprise99.

```kql
CommonSecurityLog
| where DestinationIP == "<IP>"
```
Check CommonSecurityLog for dest. ip

```kql
CommonSecurityLog
| where DestinationDomainName == "<domain name>"
```
Checks CommonSecurityLog for Dest. domain name

```kql
CommonSecurityLog
| where SourceIP == "<IP>"
```
Check CommonSecurityLog for Source IP

```kql
SignInLogs
| where SigninLogs == "<IP>"
```
Check SigninLogs for IP address

```kql
SignInLogs
| where UserPrincipalName == "<User Email>"
```
Check SigninLogs for UserPrincipalName

```kql
SecurityAlert
| where AlertName contains "ti map"
| where tostirng(Entities) !contains "23.227.38."
| summarize by tostring (Entities)
```
Check Security Alert for AlertName containing "Ti map"
<br>
The string does not contain "<ip>"
<br>
Then summarize by entities in string format

```kql
SigninLogs
| where UserPrincipalName =~ "John.Smith@domain.com" and ResultType == "0" //and IPAddress != "<IP>"
| summarize by TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, tostring(DeviceDetail)
```
Check SigninLogs for specific user, result type and/or not specific ip address
```kql
OfficeActivity
| where Operation == "New-InboxRule and UserId contains "<User's last name>"
| summarize by tostring(Parameters) and DeviceAction != "Blocked" and UserId contains "<User's last name>"
```
Check OfficeActivity for New-Inbox Rules tied to user's last name, summarize any DeviceAction that was not Blocked, show parameters in string format. Performed on compromised account.

```kql
OfficeActivity
| find "<domain>"
| summarize by tostring(Parameters)
````
find <ip/host/whatever>
<br>
To find a field that isn't showing, then use the field that appears

```kql
SigninLogs
| where UserDisplayName == "<Username>"
| project TimeGenerated, IPAddress, Location, LocationDetails, UserAgent, Status
```
Outdated default sign in logs checker

```kql
SigninLogs
| where UserPrincipalName == "John.Smith@domain.com"
| project TimeGenerated, UserDisplayName, AppDisplayName, IPAddress, Location, LocationDetails, Status, AuthenticationRequirement
```
Outdated default sign in logs checks #2

```kql
SigninLogs
| where UserPrincipalName == "John.Smith@domain.com"
| summarize count by <field>
| project TimeGenerated, UserDisplayName, LocationDetails_string, AppDisplayName, ResourceDisplayName, Status_string
```
Add to end of event logs query

```kql
SigninLogs
| where UserPrincipalName == "John.Smith@domain.com"
//| where IPAddress == "<IP>"
| summarize by TimeGenerated, UserPrincipalName, Location, tostring(Status), tostring(DeviceDetail), IPAddress, AppDisplayName, tostring(LocationDetails), AuthenticationRequirement, tostring(MfaDetail), AuthenticationDetails
```
Check SigninLogs for particular user and/or IPAddress then summarize by filters
<br>
Formerly my primary SigninLogs query

```kql
CommonSecurityLog
| where DestinationHostName == "<domain>" //and SourceIP == "<IP>"
//| where DestinationIP == "<IP>" //and SourceIP == "<IP>"
| project TimeGenerated, DeviceAction, Activity, DestinationHostName, RequestURL, RequestContext, SourceIP, SourceUserName, SourceTranslatedAddress
```
Check CommonSecurityLog for DestinationhostName and/or SourceIP, and/or DestinaionIP and/or SourceIP then project using filters
<br>
Formerly my primary CommonSecurityLog query
```kql
AzureActivity
| where Caller == "<alphanumeric>"
```
Basic AzureActivity, searches for caller

```kql
DeviceInfo
| where OnboardingStatus == "Can be onboarded" and OSPlatform contains ("WindowsServer")
```
Simplified KQL query for looking for servers to be onboarded. Wed Theme (EDR) day specific.
<br>
Still needs fine-tuning. Something exists within defender which makes this query unusable. I need to ifugre out what this is then apply it here

```kql
DeviceInfo
| where OnboardingStatus == "Can be onboarded" and OSPlatform contains ("WindowsServer")
| where DeviceCategory contains "Endpoint"
| distinct DeviceName
```
Resolved the above via:
<br>
Utilization of time
<br>
Specifying the need for endpoints
<br>
Utilizing distinct to minimise results

```kql
DeviceInfo
| where OnboardingStatus == "Can be onboarded" and OSPlatform contains ("WindowsServer")
| where DeviceCategory contains "Endpoint"
| distinct DeviceName, OSPlatform, OSVersionInfo, DeviceType, OnboardingStatus
```
More honed in results of the above
<br>
Can be utilized in Wed Theme Day

```kql
IdentityInfo
| where AccountUpn == "<user>"
| distinct AccountUpn, CreatedDateTime, JobTitle, City, Country
```
KQL query for fast identityinfo acquisition of user

```kql
IdentityInfo
| where AccountUpn == "<user>"
| distinct AccountUpn, IsAccountEnabled, CreatedDateTime, JobTitle, City, Country
```
Above but now with new and improved IsAccountEnabled

```kql
IdentityInfo
| where AccountUPN == "<user>"
| distinct AccountUPN, IsAccountEnabled, AccountCreationTime, JobTitle, City, Country
```
Sentinel specific

```kql
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
```
Above but has addition of DeviceInfo to enrich the information more
<br>
Broken current however, provides results but the results are blank


```kql
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
```
Fixed above using this kql query

```kql
DeviceFileEvents
| where FileName endswith ".crx"
```
Review files for file format: .crx (chrome web extensions)

```kql
DeviceNetworkEvents
| where Timestamp between (ago(5h) .. ago(3h))
| where DeviceName contains "<device.internaldomain>" //and RemoteIP == "<IP>"
```
Check DeviceNetworkEvents for activity between timestamps (2h period) for particular device and IP. Associated with "Hunt for related activity"

```kql
let selectedTimestamp = datetime(<time>)
search in (DeviceNetworkEvents)
Timestamp between ((selectedTimestamp - 30m) .. (selectedTimestamp + 30m))
and DeviceName == "<device>"
| sort by Timestamp desc
| extend Relevance = ifff(Timestamp == selectedTimestamp, "Selected event", ifff(Timestamp < selectedTimestamp, "Earlier event", "Later event"))
| project-reorder Relevance
```
Check DeviceNetworkEvents for particular device related activity during specific time. Automated query from "Hunt for related events" in Device Timeline. No added filters alongside relevance

```kql
let selectedTimestamp = datetime(<time>)
search in (DeviceNetworkEvents)
Timestamp between ((selectedTimestamp - 30m) .. (selectedTimestamp + 30m))
and DeviceName == "<device>"
| sort by Timestamp desc
| extend Relevance = ifff(Timestamp == selectedTimestamp, "Selected event", ifff(Timestamp < selectedTimestamp, "Earlier event", "Later event"))
| project-reorder Relevance, RemoteUrl, RemoteIP
```
Check DeviceNetworkEvents for particular device related actvity during specific time. Automated query from "Hunt for related events" in Device Timeline but honed in with extra project-reorder filters

```kql
AADServicePrincipalSigninLogs
| where IPAddress == "<IP>"
| project by TimeGenerated, ServicePrincipalName, Location, ConditionalAccessStatus, IPAddress, LocationDetails, ResultType
```
Useful for unusual data center login

```kql
AzureDiagnostics
| where userAgent_s == "<useragent>"
| project TimeGenerated, clientIP_s, clientIp_s, httpStatusCode_d
```
Check AzureDiagnostics for particular Malformed User Agent

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName contains "<device>"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort
```
Useful for TI Maps, review browsing activity for particular device over 7 day period

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP contains "<IP>"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort
```
Useful for TI Maps, review browsing activity for particular IP over 7 day period

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl contains "<Url>"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort
```
Useful for TI Maps, review browsing activity for particular url/domain over 7 day period

```kql
AADNonInteractiveSigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "<User>"
//| where IPAddress == "<IP>"
//| where AppDisplayName == "<App>"
//| where ResultType contains "53005"
| summarize by TimeGenerated, UserPrincipalName, Location, tostring(Status), tostring(DeviceDetail), IPAddress, AppDisplayName, tostring(LocationDetails), AuthenticationRequirement, tostirng(MfaDetail), AuthenticationDetails, ResultType
```
Useful for failed login alerts

```kql
AzureActivity
| where Caller == "<Caller>"
| where OperationNameValue has_any ("MICROSOFT.SECURITYINSIGHTS/ALERTRULES/DELETE", "MICROSOFT.SECURITYINSIGHTS/WATCHLISTS/DELETE")
| project TimeGenerated, OperationNameValue, ResourceGroup, Caller, CallerIpAddress, Type
```
Useful for mass cloud resource deletion

```kql
DeviceNetworkEvents
| where RemoteUrl contains "libgen"
| summarize count() by RemoteUrl
```
Displays urls associated to suspicious domain - ti map related - wider search for activity related to a suspicious domain

```kql
DeviceNetworkEvents
| where DeviceName contains "<Device>"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessVersionInfoInternalFileName
```
Check DeviceNetworkEvents for devicename, then project using filters - ti map specific

```kql
Syslog
| where TimeGenerated > ago(4d)
| where SyslogMessage contains "<svc account>"
| project TimeGenerated, SyslogMessage
```
Useful for Multiple RDP connections made by a single system

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Cyber-Ark" and DeviceProduct == "Vault" //and DeviceEventClassID == "309"
| where SourceUserName == "<user>"
| project TimeGenerated, DeviceEventClassID, Activity, SourceUserName
```
Check commonsecuritylog for CyberArk activity - Useful for: CCX - CyberArk Undefined User Login

```kql
AzureDiagnostics
| where userAgent_s == "<useragent>"
| where timestamp == <time>
| project TimeGenerated, clientIP_s, clientIp_s, httpStatusCode_d
```
Check AzureDiagnostics for particular Malformed User Agent

```kql
let selectedTimestamp = datetime('YYYY-MM-DDTHH:MM:SS.MSZ')
CommonSecurityLog
| where TimeGenerated between ((selectedTimestamp - 30m) .. (selectedTimestamp + 30m))
//| where DestinationHostName == "<Domain>" //and SourceIP == "<IP>"
| where DestinationIP == "<IP>" //and SourceIP == "<IP>"
| project TimeGenerated, DeviceVendor, DeviceProduct, DeviceAction, Activity, DestinationHostName, DestinationIP, DestinationPort, SourceIP, SourcePort, RequestURL, RequestContext, SourceUserName, SourceTranslatedAddress
```
Check CommonSecurityLog for specific timestamp 30mins forwards and backwards via the Dest. IP, then project results
