# KUMyMeterPS
Use PowerShell to pull your LG&amp;E KU MyMeter usage statistics!</br>

## Examples
```
#User/Pass input box will appear if credentials not provided
Connect-KUMyMeter

Connect-KUMyMeter -Username "UserHere" -Password "PassHere"

$Meters = Get-KUMyMeterMeters

$MeterUsageData = Get-KUMyMeterUsage

$MeterUsageData = Get-KUMyMeterUsageAdvanced -DisplayMeter "All Usage" -UsageRange "FifteenMinByDay" -UsageType "Dollar($)"

$AccessLogs = Get-KUMyMeterAccessLog

$RegisteredUsers = Get-KUMyMeterRegisteredUsers

$AdditionalAccessUsers = Get-KUMyMeterAdditionalUsers

$MyMeterBillingHistory = Get-KUMyMeterBillingHistory

$MyMeterBillingHistory = Get-KUMyMeterBillingHistory -StartDate "2023-06-01" -EndDate "2023-10-31" -DownloadToCSVFile "C:\Users\Username\Documents\MyMeterBilling.csv"
```
<br/>
<br/>
The '<b>Connect-KUMyMeter</b>' function can be ran with or without paramters!</br></br>
