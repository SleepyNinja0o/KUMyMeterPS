# KUMyMeterPS
Use PowerShell to pull your LG&amp;E KU MyMeter usage statistics!</br>

## Examples
```
Connect-KUMyMeter -Username "UserHere" -Password "PassHere"

$MyMeters = Get-KUMyMeterMeters

$MeterData = Get-KUMyMeterUsage

$MeterDataAdvanced = Get-KUMyMeterUsageAdvanced -DisplayMeter $MyMeters['Meter #1234567GEN (Residential Service - All Electric) - Energy Charge'] -UsageRange "FifteenMinByDay" -UsageType = "Dollar($)"
```
<br/>
<br/>
The '<b>Connect-KUMyMeter</b>' function can be ran with or without paramters!</br></br>
