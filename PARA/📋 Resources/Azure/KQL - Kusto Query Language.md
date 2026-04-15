---
tags:
  - "#Azure"
  - "#KQL"
  - "#SIEM"
date: 2026-02-25
---
# KQL - Kusto Query Language
Kusto Query Language (KQL) is a powerful, read-only language used to query, analyze, and visualize structured, semi-structured, and unstructured data. Developed by Microsoft, it is the primary language for Azure Data Explorer, Azure Monitor, and Microsoft Sentinel.



___
## Search Operator
Search across all columns in all tables for a value:
```kql
search "Computer"
```

Search within specific tables (supports wildcards):
```kql
search in (SecurityEvent_CL, App*) "new"
```

> **Note:** `search` without specific tables or qualifying clauses is inefficient compared to table-specific and column-specific filtering.



---
## Where Operator
Filter on a specific predicate. Multiple `where` clauses can be piped or combined with `and`.
```kql
SecurityEvent_CL
| where TimeGenerated > ago(7d)
```

```kql
SecurityEvent_CL
| where TimeGenerated > ago(7d) and EventID_s == 4624
```

Case-insensitive comparison with `=~`:
```kql
SecurityEvent_CL
| where TimeGenerated > ago(7d)
| where EventID_s == 4624
| where AccountType_s =~ "user"
```

Using `in` to match multiple values:
```kql
SecurityEvent_CL
| where TimeGenerated > ago(7d) and EventID_s in (4624, 4625)
```

> When filtering with `TimeGenerated`, the Time range in the UI switches to "Set in query".



---
## Let Statements
Declare variables:
```kql
let timeOffset = 10m;
let discardEventID = 4688;
SecurityEvent_CL
| where TimeGenerated > ago(timeOffset*60) and TimeGenerated < ago(timeOffset)
| where EventID_s != discardEventID
```

Declare a dynamic list with `datatable`:
```kql
let suspiciousAccounts = datatable(account: string) [
  @"NA\timadmin",
  @"NT AUTHORITY\SYSTEM"
];
SecurityEvent_CL
| where TimeGenerated > ago(7d)
| where Account_s in (suspiciousAccounts)
```

Declare a dynamic table (subquery as variable):
```kql
let LowActivityAccounts =
    SecurityEvent_CL
    | summarize cnt = count() by Account_s
    | where cnt < 1000;
LowActivityAccounts | where Account_s contains "sql"
```



---
## Summarize Operator
Groups rows by columns and calculates aggregations over each group.
### count()
```kql
SecurityEvent_CL
| where TimeGenerated > ago(7d) and EventID_s == 4688
| summarize count() by Computer
```

Named count column:
```kql
SecurityEvent_CL
| where TimeGenerated > ago(7d) and EventID_s == 4624
| summarize cnt=count() by AccountType_s, Computer
```

### dcount()
Returns an approximate distinct count of group elements:
```kql
SigninLogs_CL
| where TimeGenerated > ago(7d)
| summarize dcount(IPAddress)
```

Practical example - detect disabled accounts failing across multiple apps:
```kql
let timeframe = 30d;
let threshold = 1;
SigninLogs_CL
| where TimeGenerated >= ago(timeframe)
| where ResultDescription has "User account is disabled"
| summarize applicationCount = dcount(AppDisplayName_s) by UserPrincipalName_s, IPAddress
| where applicationCount >= threshold
```

### arg_max() / arg_min()
`arg_max` returns the row where the argument is maximized. `*` pulls all columns:
```kql
SecurityEvent_CL
| where Computer == "VictimPC2"
| summarize arg_max(TimeGenerated, *) by Computer
```

`arg_min` returns the row where the argument is minimized (oldest entry):
```kql
SecurityEvent_CL
| where Computer == "VictimPC2"
| summarize arg_min(TimeGenerated, *) by Computer
```

### Pipe Order Matters
**Query 1** - Accounts whose _last activity_ was a login (summarize first, then filter):
```kql
SecurityEvent_CL
| summarize arg_max(TimeGenerated, *) by Account_s
| where EventID_s == 4624
```

**Query 2** - Most recent login for accounts that _have_ logged in (filter first, then summarize):
```kql
SecurityEvent_CL
| where EventID_s == 4624
| summarize arg_max(TimeGenerated, *) by Account_s
```

> These return different results. Check "Query details" to compare CPU and data usage.

### make_list() vs make_set()
`make_list` — JSON array of all values (includes duplicates):
```kql
SecurityEvent_CL
| where TimeGenerated > ago(7d)
| where EventID_s == 4624
| summarize make_list(Account_s) by Computer
```

`make_set` — JSON array of distinct values only:
```kql
SecurityEvent_CL
| where TimeGenerated > ago(7d)
| where EventID_s == 4624
| summarize make_set(Account_s) by Computer
```



---
## Render Operator (Visualizations)
Bar chart:
```kql
SecurityEvent_CL
| where TimeGenerated > ago(7d)
| summarize count() by Account_s
| render barchart
```

Time series with `bin()` — rounds values into time buckets:
```kql
SecurityEvent_CL
| where TimeGenerated > ago(7d)
| summarize count() by bin(TimeGenerated, 1m)
| render timechart
```



---
## Multi-Table Statements
### Union
Combines rows from multiple tables.
All rows from both tables:
```kql
SecurityEvent_CL
| union SigninLogs_CL
```

Total count across both:
```kql
SecurityEvent_CL
| union SigninLogs_CL
| summarize count()
```

All SecurityEvent rows + a summary count row from SigninLogs:
```kql
SecurityEvent_CL
| union (SigninLogs_CL | summarize count() | project count_)
```

Wildcard union:
```kql
union Sec*
| summarize count() by Type
```

### Join
Merges rows from two tables by matching column values. First table = left, table after `join` = right.
```kql
SecurityEvent_CL
| where EventID_s == 4624
| summarize LogOnCount=count() by EventID_s, Account_s
| project LogOnCount, Account_s
| join kind = inner(
  SecurityEvent_CL
  | where EventID_s == 4634
  | summarize LogOffCount=count() by EventID_s, Account_s
  | project LogOffCount, Account_s
) on Account_s
```

> Join types: `fullouter`, `inner`, `innerunique`, `leftanti`, `leftantisemi`, `leftouter`, `leftsemi`, `rightanti`, `rightantisemi`, `rightouter`, `rightsemi`. Use `$left.Column` and `$right.Column` to disambiguate.



---
## String Operations
### extract()
Regex extraction from a string. Second argument is the capture group index:
```kql
print extract("x=([0-9.]+)", 1, "hello x=45.6|wo") == "45.6"
```

Extract account name from domain\user format:
```kql
SecurityEvent_CL
| where EventID_s == 4672 and AccountType_s == 'User'
| extend Account_Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account_s))
| summarize LoginCount = count() by Account_Name
| where Account_Name != ""
| where LoginCount < 10
```

### parse
Parses a string expression into calculated columns — useful for unstructured data:
```kql
let Traces = datatable(EventText:string)
[
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=23, lockTime=02/17/2016 08:40:01, releaseTime=02/17/2016 08:40:01, previousLockTime=02/17/2016 08:39:01)",
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=15, lockTime=02/17/2016 08:40:00, releaseTime=02/17/2016 08:40:00, previousLockTime=02/17/2016 08:39:00)",
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=20, lockTime=02/17/2016 08:40:01, releaseTime=02/17/2016 08:40:01, previousLockTime=02/17/2016 08:39:01)",
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=22, lockTime=02/17/2016 08:41:01, releaseTime=02/17/2016 08:41:00, previousLockTime=02/17/2016 08:40:01)",
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=16, lockTime=02/17/2016 08:41:00, releaseTime=02/17/2016 08:41:00, previousLockTime=02/17/2016 08:40:00)"
];
Traces
| parse EventText with * "resourceName=" resourceName ", totalSlices=" totalSlices:long * "sliceNumber=" sliceNumber:long * "lockTime=" lockTime ", releaseTime=" releaseTime:date "," * "previousLockTime=" previousLockTime:date ")" *
| project resourceName, totalSlices, sliceNumber, lockTime, releaseTime, previousLockTime
```



---
## Working with JSON
Parse JSON fields and extract values:
```kql
SigninLogs_CL
| extend AuthDetails = parse_json(AuthenticationDetails_s)
| extend AuthMethod = AuthDetails[0].authenticationMethod
| extend AuthResult = AuthDetails[0].["authenticationStepResultDetail"]
| project AuthMethod, AuthResult, AuthDetails
```

### mv-expand
Expand dynamic arrays into individual rows:
```kql
SigninLogs_CL
| mv-expand AuthDetails = parse_json(AuthenticationDetails_s)
| project AuthDetails
```

### mv-apply
Apply a subquery to each record, return the union of results:
```kql
SigninLogs_CL
| mv-apply AuthDetails = parse_json(AuthenticationDetails_s) on
(where AuthDetails.authenticationMethod == "Password")
```



---
## Saving Functions
After running a query, use **Save > Save As function** to reuse it by alias:
```kql
NameOfAlias
```

Set a **Function name** and a **Legacy category** (e.g., General) when saving.








---
# Resources
- [Microsoft Learn - Kusto Query Language overview]([https://github.com/groepl/Obsidian-Templates#basic-template-structure](https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric))