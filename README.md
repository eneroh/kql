# kql

## Summary
This README houses queries that I have utilized. Inspiration for this document, my upskilling and some queries goes to reprise99, as well as: https://learnsentinel.blog/tag/kql/ and https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/microsoft-defender-for-endpoint-commonly-used-queries-and/ba-p/1795046?ref=rbwilson.ca

## Commands/operators/functions overview
```kql
let
```
Allows you to create a variable and call back to it in a later instance (time, url, device)
```kql
union
```
Combine multiple device query tables (union DeviceProcessEvents, DeviceNetworkEvents)
```kql
join
```
Merge the rows of two tables to form a new table by matching values of the specified columns for each table
```kql
distinct
```
Acts as dedup in SPL, only focuses on results that are special, no duplicates
```kql
dcount()
```
Function - Calculates an estimate of the number of distinct values that are taken by scaler expression in the summary group. Null is ignored entirely.
```kql
top
top 100 by MachineCount
top 10 by avg_CPU
top 50 by Timestamp
```
Displays top X results
```kql
extend
extend = Duration = EndTime - StartTime
```
Create calculated columns and appends them to the result
```kql
project
| project TimeGenerated
| project StartLocation =  BeginLocation, TotalInjuries = InjuriesDirect + InjuriesIndirect
| where Totalinjuries > 5
```
Create columes, features: rename, drop, insert new computed columns, column order is specified by the order or arguments
```kql
summarize
```
Produces a table that aggregates the content of the input table. Can be used for extra features such as creating visualisations and counts
```kql
parse_json()
```
Function - Interprets string as JSON value, returns value as dynamic
```kql
extract_json()
```
Function - When you need to extract more than one element of a JSON compound object. Use dynamic() when possible
```kql
tostring()
```
Function - Very commonly used with summarize to convert a value to a string (specifically numbers i.e. tostring(123)

```kql
series_stats()
print x=dynamic([23, 46, 23, 87, 4, 8, 3, 75, 2, 56, 13, 75, 32, 16, 29]) 
| project series_stats(x)
```
Function - Returns statistics for numerical series in a table with a column for each statistic

```kql
count
CommonSecurityLog
| count
```
Operator - Returns the number of records for the input record set

```kql
count()
StormEvents
| summarize Count=count() by State
```
Function - Counts the number of records per summarization group or total if summarization is done without grouping. Null values are ignored entirely.

## Useful KQL Queries

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
Check AzureDiagnostics for particular Malformed User Agent (old)

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
Check commonsecuritylog for CyberArk activity - Useful for: <custom> - CyberArk Undefined User Login

```kql
AzureDiagnostics
| where userAgent_s == "<useragent>"
| where timestamp == <time>
| project TimeGenerated, clientIP_s, clientIp_s, httpStatusCode_d
```
Check AzureDiagnostics for particular Malformed User Agent (improved)

```kql
let selectedTimestamp = datetime('YYYY-MM-DDTHH:MM:SS.MSZ')
CommonSecurityLog
| where TimeGenerated between ((selectedTimestamp - 30m) .. (selectedTimestamp + 30m))
//| where DestinationHostName == "<Domain>" //and SourceIP == "<IP>"
| where DestinationIP == "<IP>" //and SourceIP == "<IP>"
| project TimeGenerated, DeviceVendor, DeviceProduct, DeviceAction, Activity, DestinationHostName, DestinationIP, DestinationPort, SourceIP, SourcePort, RequestURL, RequestContext, SourceUserName, SourceTranslatedAddress
```
Check CommonSecurityLog for specific timestamp 30mins forwards and backwards via the Dest. IP, then project results

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| summarize avg(CPU) by ProcessName
| top 10 by avg_CPU
```
Returns the top 10 processes by CPU usage in the last hour

```kql
DeviceFileEvents 
| where SHA1 == "4aa9deb33c936c0087fb05e312ca1f09369acd27"  
```
Check DeviceFileEvents for SHA1 file hash

```kql
DeviceEvents 
| where ActionType in ("FirewallOutboundConnectionBlocked", "FirewallInboundConnectionBlocked", "FirewallInboundConnectionToAppBlocked") 
| project DeviceId , Timestamp , InitiatingProcessFileName , InitiatingProcessParentFileName, RemoteIP, RemotePort, LocalIP, LocalPort 
| summarize MachineCount=dcount(DeviceId) by RemoteIP 
| top 100 by MachineCount desc 
```
Check DeviceEvents for devices associated with Firewall Blocked

```kql
DeviceLogonEvents 
| where isnotempty(RemoteIP)  
    and AccountName !endswith "$" 
    and RemoteIPType == "Public" 
| extend Account=strcat(AccountDomain, "\\", AccountName) 
| summarize  
    Successful=countif(ActionType == "LogonSuccess"), 
    Failed = countif(ActionType == "LogonFailed"), 
    FailedAccountsCount = dcountif(Account, ActionType == "LogonFailed"), 
    SuccessfulAccountsCount = dcountif(Account, ActionType == "LogonSuccess"), 
    FailedAccounts = makeset(iff(ActionType == "LogonFailed", Account, ""), 5), 
    SuccessfulAccounts = makeset(iff(ActionType == "LogonSuccess", Account, ""), 5) 
    by DeviceName, RemoteIP, RemoteIPType 
| where Failed > 10 and Successful > 0 and FailedAccountsCount > 2 and SuccessfulAccountsCount == 1  
```
Look for public IP addresses with multiple failed logon attempts, using multiple accounts and eventually succeeded

```kql
// Note - RemoteDeviceName is not available in all remote logon attempts 
DeviceLogonEvents 
| where isnotempty(RemoteDeviceName) 
| extend Account=strcat(AccountDomain, "\\", AccountName) 
| summarize  
    Successful=countif(ActionType == "LogonSuccess"), 
    Failed = countif(ActionType == "LogonFailed"), 
    FailedAccountsCount = dcountif(Account, ActionType == "LogonFailed"), 
    SuccessfulAccountsCount = dcountif(Account, ActionType == "LogonSuccess"), 
    FailedComputerCount = dcountif(DeviceName, ActionType == "LogonFailed"), 
    SuccessfulComputerCount = dcountif(DeviceName, ActionType == "LogonSuccess") 
    by RemoteDeviceName 
| where 
    Successful > 0 and 
    ((FailedComputerCount > 100 and FailedComputerCount > SuccessfulComputerCount) or 
        (FailedAccountsCount > 100 and FailedAccountsCount > SuccessfulAccountsCount)) 
```
Check DeviceLogonEvents for failed log-ons to multiple machines or using multiple accounts

```kql
DeviceEvents 
| where ActionType in ("AntivirusScanCompleted", "AntivirusScanCancelled") 
| extend A=parse_json(AdditionalFields)  
| project Timestamp, DeviceName, ActionType,ScanType = A.ScanTypeIndex, StartedBy= A.User 
| sort by Timestamp desc 
```
Check DeviceEvents for Defender Scan Actions completed or cancelled

```kql
let Domain = "<suspicious domain/url>";
DeviceNetworkEvents
| where Timestamp > ago(7d) and RemoteUrl contains Domain
| project Timestamp, DeviceName, RemotePort, Remoteurl
| top 100 by Timestamp desc
```
Check DeviceNetworkEvents for communication with specific domain/url

```kql
union DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","powershell_ise.exe")
| where ProcessCommandLine has_any("WebClient","DownloadFile","DownloadData","DownloadString","WebRequest","Shellcode","http","https")
| project Timestamp, DeviceName, InitiatingProcessFuileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, RemoteIPType
| top 100 by Timestamp
```
Check DeviceProcessEvents and DeviceNetworkEvents via union (combine multiple device query tables), for powershell execution events associated with downloading

```kql
DeviceProcessEvents 
| where FolderPath endswith "\\schtasks.exe" and ProcessCommandLine has "/create" and AccountName != "system" 
| where Timestamp > ago(7d) 
```
Check DeviceProcessEvents for scheduled tasks created by non-system accounts

```kql
DeviceRegistryEvents  
| where ActionType == "RegistryValueSet"  
| where RegistryValueName == "DefaultPassword"  
| where RegistryKey has @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 
| project Timestamp, DeviceName, RegistryKey | top 100 by Timestamp 
```
Check DeviceRegistryEvents for possible clear text passwords in twindows registry

```kql
DeviceProcessEvents 
| where Timestamp > ago(14d) 
| where ProcessCommandLine contains ".decode('base64')" or ProcessCommandLine contains "base64 --decode" or ProcessCommandLine contains ".decode64(" 
| project Timestamp , DeviceName , FileName , FolderPath , ProcessCommandLine , InitiatingProcessCommandLine  
| top 100 by Timestamp 
```
CheckProcessEvents for process executed from binary hidden in base64 encoded file

```kql
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(30d)
| where ServicePrincipalId contains "<ObjectId>"
| project TimeGenerated, Category, IPAddress, Location, LocationDetails, ResourceDisplayName
```
Check AADServicePrincipalSignInLogs for activity associated to CallerObjectId - Useful for reviewing signinlogs for mass resource cloud deletion, mass secret retrieval from azure key vault etc.

```kql
OfficeActiviy
| where TimeGenerated > ago(7d)
| where UserId contains "<user>"
| where Operation has_any ("MemberRemoved","MemberAdded")
| project TimeGenerated, RecordType, Operation, UserId, ClientIP, Members, ItemName
```
Check OfficeActivity for specific timeframe, userid, operation then project results - Useful for External user added and removed in short timeframe

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
//| where UserId contains "<user>"
| where Members contains "<user being removed>"
| where Operation has_any ("MemberRemoved","MemberAdded")
| project TimeGenerated, RecordType, Operation, UserId, ClientIP, Members, ItemName
```
Wider scope of the above to provide a bigger picture of what is occurring

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName contains == "<User>"
//| where IPAddress contains "<IP"
//| where AppDisplayName contains "<App>"
//| where ResultType contains "0"
| project TimeGenerated, UserPrincipalName, Location, Status, DeviceDetail, IPAddress, AppDisplayName, LocationDetails, AuthentictionRequirement, MfaDetail, AuthenticationDetails, ResultType
```
Utilizing contains instead of ==, more forgiving than my old SigninLogs query

```kql
AADNonInteractiveSignInLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName contains == "<User>"
//| where IPAddress contains "<IP"
//| where AppDisplayName contains "<App>"
//| where ResultType contains "0"
| project TimeGenerated, UserPrincipalName, Location, Status, DeviceDetail, IPAddress, AppDisplayName, LocationDetails, AuthentictionRequirement, MfaDetail, AuthenticationDetails, ResultType
```
Utilizing contains instead of ==, more forgiving than my old AADNonInteractiveSignInLogs query

```kql
AzureDiagnostics
| where ResourceProvider == "MICROSFT.CDN" and Category == "FrontDoorAccessLog"
| where TimeGenerated == <time>
//| project TimeGenerated, clientIP_s, clientIp_s, host_s, action_s
```
Check WAF - Web application firewall for particular activity - Useful for: AFD WAF - Code Injection
<br>
This is also how you access waf logs

```kql
EmailEvents
| where RecipientEmailAddress !endswith "<domain>" and Subject startwith "FW" and not(Subject contains "vaccination")
| summarize total_count=count(), distinct_recipients=dcount(RecipientEmailAddress), recipients=make_set(RecipientEmailAddress), subject_list=make_set(Subject), distinct_subject=dcount(Subject) by SenderFromAddress
| where distinct_recipients <= 2 and total_count > 10 and distinct_subject >= 10
| sort by total_count desc
```
Check EmailEvents for emails being forward (data exfiltration) to external mail account

```kql
AuditLogs
| where InitiatedBy contains "<user>"
| where OperationName in ("Add conditional access policy","Update conditional access policy","Delete conditional access policy")
```
Check AuditLogs for conditional access policy changes

```kql
OfficeActivity
| where UserId contains "<user>"
| where Operation contains "Deleted"
| where RecordType contains "MicrosoftTeams"
```
Check OfficeActivity for Deleted activity associated to user and app Microsoft Teams - Useful for Mulitple team deletions by user

```kql
OfficeActivity
| where TimeGenerated > ago(30d)
//| where UserId contains "<user>"
| where Operation contains "TeamDeleted"
| where RecordType contains "MicrosoftTeams"
```
Check OfficeActivity for multiple users associated to team deletions in Microsoft Teams

```kql
AuditLogs
| where OperationName startswith "Delete conditional access policy"
| project TimeGenerated, OperationName, Id, InitiatedBy, Result, TargetResources, AADOperationType
```
Check AuditLogs for OperationName then project filters - Useful for: Conditional access policy changes

```kql
AADServicePrincipalSignInLogs
| where ServicePrincipalId == "<Caller>"
| where IPAddress == "<IP>"
```
Check ServicePrincipalSignInLogs for suspicious activity associated to Service Principal account - Useful for: Suspicious Resource Deployment

```kql
AzureActivity
| where TimeGenerated == todatetime('<time>')
| where Caller == "<Caller>"
| where OperationNameValue has_any ("MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE")
```
Check AzureActivity for specific activity associated to caller, operation at particular time - Useful for: Suspicious Resource Deployment

```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where Caller == "<Caller>"
| where OperationNameValue has_any ("MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE")
```
Check AzureActivity for specific activity but do a wider lens - Useful for: Suspicious Resource Deployment

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("FileDownloaded","FileSyncDownloadedFull")
| where OfficeObjectId contains "<Sharepoint file location"
```
Check OfficeActivity for particular file that is associated to Mass Download alert

```kql
CommonSecurityLog
| where TimeGenerated > ago(10m)
| where DeviceVendor contains "<Network Appliance>"
| sort by TimeGenerated
| take 10
```
Check CommonSecurityLog for network appliance activity - Useful for: Automatic log upload error
<br>
(Confirm if network appliance is gathering logs)

```kql
search in (<table>,<table>,<table>) "text/IP"
| where TimeGenerated > ago(3d)
| distinct UserPrincipalName
```
Check singular/multiple tables for particular text/IP, for particular time period and unique user, can edit further for project/distinct and create charts etc.

```kql
SignInLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName contains "<User>"
| where Location !in ("AU","NZ")
//| where IPAddress in ("<IP>")
//| where AppDisplayName == "<App>"
//| where ResultType == "0"
| distinct IPAddress, Location, ResultDescription
```
Check SignInLogs for a particular user, not in location AU or NZ over the last 30 day period, then present only distinct IP addresses, followed by location and resultdescription associated to the distinct IP addresses.
<br>
Can be honed forward or back depending.

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName contains == "<User>"
//| where IPAddress contains "<IP"
//| where AppDisplayName contains "<App>"
//| where ResultType contains "0"
| project TimeGenerated, UserPrincipalName, Location, Status, DeviceDetail, IPAddress, AppDisplayName, LocationDetails, AuthentictionRequirement, MfaDetail, AuthenticationDetails, ResultType, tostring(ConditionalAccessPolicies)
```
My main query but with the addition of ConditionalAccessPolicies

```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue in ("MICROSOFT.AUTHORIZATION/POLICIES/DENY/ACTION")
| where Caller contains "<user>"
//| where Properties contains "Prevent <policy details>"
```
Check AzureActivity for attempts to bypass policy by user over the last 7 day period
<br>
Useful for: Attempted creation of external resource

```kql
search in (AADManagedIdentitySignInLogs) "<ServicePrincipalId>"
| where TimeGenerated > ago(5d)
| project TimeGenerated, ServicePrincipalId, AppId, Type
```
Check AADManagedIdentitySignInLogs for ServicePrincipalId over the last 5 day period then filter results using project, you can also comment out the project to see all results

```kql
AADManagedIdentitySignInLogs
| where TimeGenerated > ago(5d)
| where ServicePrincipalId contains "<ServicePrincipalId>"
| project TimeGenerated, ServicePrincipalId, AppId, Type
```
Check AADManagedSignInLogs, ServicePrincipalId over the last 5 day period then filter results with project, you can also comment out the project to see all results

```kql
SignInLogs
| where TimeGeneated > ago(30d)
| where UserPrincipalName contains "<user>" and AppDisplayName != "Bing"
| where Location != "<User primary location as per EntraID>"
| distinct IPAddress, Location, ResultType, Status
```
Displays all UNIQUE ip addresses associated with user that are typically failed and not in user's regular EntraID location

```kql
SignInLogs
| where TimeGenerated > ago(30d)
| where IPAddress in("<Suspicious IP>")
| summarize by TimeGenerated, UserPrincipalName, Location, tostring(Status), tostring(DeviceDetail), IPAddress, AppDisplayName, tostring(LocationDetails), AuthenticationRequirement, tostring(MfaDetail), AuthenticationDetails, ResultType, tostring(ConditionalAccessPolicies)
```
Displays all activity associated with suspicious IP address then filtering them in a manner that is acceptable

```kql
union DeviceProcessEvents, DeviceFileEvents
| where MD5 has_any ("<file_hash1>","<file_hash2>","<file_hash3>")
| project-reorder TimeGenerated, Type, ActionType, FileName, MD5, DeviceName
| sort by TimeGenerated, desc
```
Displays devices associated with suspicious MD5 hash then filters and sorts that data using respective filters

```kql
SignInLogs
| where TimeGeneated > ago(30d)
| where UserPrincipalName contains "<user>" and AppDisplayName contains "Powershell"
| summarize by TimeGenerated, UserPrincipalName, Location, tostring(Status), tostring(DeviceDetail), IPAddress, AppDisplayName, tostring(LocationDetails), AuthenticationRequirement, tostring(MfaDetail), AuthenticationDetails, ResultType, tostring(ConditionalAccessPolicies)
| distinct IPAddress, Location, ResultType, Status
```
Looks specific for a user and logins associated with Powershell, very uncommon activity for non-technical user roles. So it's good to reference their role via EntraID before making determination
<br>
Typically can involve many failed logins so it's good to be filter them so it's easier to read for remediation of: blocking suspicious IP address ranges

```kql
| where not(RemoteUrl has_any("<Domain>","<Domain>","<Domain>")
```
Limitations in KQL make it so you cannot do !contains for an array, instead you have to do things more round-a-bout but this works so we're good

```kql
| where isnotempty(<field>)
```
Displays information that is not empty

```kql
search in (AzureDiagnostics) "<Enterprise Application Account ID>"
| where TimeGenerated > ago(7d)
```
Allows for fast searching associated to Enterprise application account. Review materials associated to specific id. Associated to Sensitive Cloud related activities.

```kql
AlertInfo
| where Timestamp between (datetime(date) .. (datetime(date))
| summarize count() by Title, Category, ServiceSource
```
Check for alerts during time period to see if the event was detected by defender

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(date) .. (datetime(date))
| where DeviceName contains "<affected device>"
| search "Facebook"
| project TimeGenerated, IntiatingProcessAccountName, ActionType, InitiatingProcessName, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated desc
```
Check timeframe for user's facebook access

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(date) .. (datetime(date))
| where DeviceName contains "<affected device>"
| project TimeGenerated, IntiatingProcessAccountName, ActionType, InitiatingProcessName, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated desc
```
Check DeviceFileEvents for suspicious file activity

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(date) .. (datetime(date))
| where DeviceName contains "<affected device>"
| project TimeGenerated, IntiatingProcessAccountName, ActionType, InitiatingProcessName, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated desc
```
Display process during timeframe, typically associated with windows and chrome updates. Needs honing to be useful

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(date) .. (datetime(date))
| seach <blanket search term>
| project TimeGenerated, DeviceName, ActionType
```
Blanket search

```kql
search in (OfficeActivity) "<user>"
| where RecordType contains "MicrosoftTeams"
| where Operation contains "Deleted"
```
Check for mass deletions associated to microsoft teams for particular user

```kql
IdentityInfo
| where AccountUPN in~ ("<user1>","<user2>","<user3>")
| summarize by AccountUPN, IsAccountEnabled
```
Mass search for confirming if user's status of active or disabled. Results inaccurate, therefore manual intervention is necessary

```kql
LAQueryLogs
| where TimeGenereated > ago(7d)
| where AADEmail contains "<kql user>"
| project AADEmail, Query
```
Review user kql logs, typically in use by seniors to review activity of underlings

```kql

```
