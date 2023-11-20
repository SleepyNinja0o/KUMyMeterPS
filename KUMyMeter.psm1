$ProgressPreference = "SilentlyContinue"

<#   ***EXAMPLE USAGE***
Connect-KUMyMeter -Username "UserHere" -Password "PassHere"

$Meters = Get-KUMyMeterMeters

$MeterData = Get-KUMyMeterUsage

$MeterData = Get-KUMyMeterUsageAdvanced -DisplayMeter "All Usage" -UsageRange = "FifteenMinByDay" -UsageType = "Dollar($)"
#>

function Connect-KUMyMeter{
param($Username,$Password)
    $Global:LGEKU_Server = "https://lge-ku.com"
    $Global:MyLGEKU_Server = "https://my.lge-ku.com"
    $Global:KUMyMeter_Server = "https://mymeter.lge-ku.com"
    #Verify site is reachable and retrieve Form ID + Form Token required for login request
    try{
        $global:wr = Invoke-RestMethod $LGEKU_Server -UseBasicParsing -SessionVariable Global:KUMyMeter_Session
        $global:FormBuildID = ($wr | Select-String -Pattern "name=""form_build_id"" value=""(.*)"" ").Matches.Groups[1].value
        $global:FormToken = ($wr | Select-String -Pattern "name=""form_token"" value=""(.*)"" ").Matches.Groups[1].value
    }catch{
        Write-Host "Unable to reach the LG&E KU login page!`n$($_.Exception.Message)" -ForegroundColor Red
        return
    }

    #Repeat login process until it is successful
    $LoginFailure = $False
    while($True){
        #If username/passsword is not provided, ask user
        if($Username -and -not ($Password)){
            $LoginFailure = $False
            $Creds = Get-Credential -Message "Please enter your KU credentials" -UserName $UserName
        }elseif(-not ($Username -and $Password) -or $LoginFailure){
            $LoginFailure = $False
            $Creds = Get-Credential -Message "Please enter your KU credentials"
        }

        $Username = $Creds.GetNetworkCredential().UserName
        $Password = $Creds.GetNetworkCredential().Password

        #Attempt login web request
        $KUMyMeter_Login_Data = @{
            'j_username' = $Username
            'j_password' = $Password
            'form_build_id' = $FormBuildID
            'form_token' = $FormToken
            'form_id' = 'lke_myaccount_login_form'
            'op' = 'Submit'
            'remote' = ''
        }
        try{
            $global:wr1 = Invoke-WebRequest -UseBasicParsing -Uri "$MyLGEKU_Server/cs/logon.sap" -Method "POST" -WebSession $KUMyMeter_Session -ContentType "application/x-www-form-urlencoded" -Body $KUMyMeter_Login_Data
            Remove-Variable -Name Password -Force -ErrorAction SilentlyContinue
            Remove-Variable -Name KUMyMeter_Login_Data -Force -ErrorAction SilentlyContinue
        }catch{
            $LoginFailure = $True
            Write-Host "Error occured during the login request!`n$($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        #If login authentication fails, return to top of while loop, else exit the loop
        if($wr1.Content -match "User authentication failed"){
            $LoginFailure = $True
            Write-Host "`nUser authentication failed. Your email and/or password are incorrect. Please try again!`n" -ForegroundColor Red
            continue
        }else{
            break
        }
    }

    #Start KU account selection process
    $wr2 = Invoke-RestMethod "$MyLGEKU_Server/cs/doSwitch.sap" -WebSession $KUMyMeter_Session
    $wr2 = $wr2.Substring($wr2.IndexOf("frmSelectAccount"))
    $xsrfid = [System.Net.WebUtility]::UrlEncode($(($wr2 | Select-String -Pattern "name=""xsrfid"" value=""(.*)""/").Matches.Groups[1].value))
    $as_sfid = [System.Net.WebUtility]::UrlEncode($(($wr2 | Select-String -Pattern "name=""as_sfid"" value=""(.*)"" /><input").Matches.Groups[1].value))
    $as_fid = [System.Net.WebUtility]::UrlEncode($(($wr2 | Select-String -Pattern "name=""as_fid"" value=""(.*)"" /").Matches.Groups[1].value))

    #Pull all sub-accounts(places) associated with current KU account
    $Global:KU_Accounts = Invoke-RestMethod "$MyLGEKU_Server/cs/getAcctListAjax.ajax" -WebSession $KUMyMeter_Session -Method Post -ContentType "application/x-www-form-urlencoded; charset=UTF-8" -Headers @{
      "accept"="application/json, text/javascript, */*; q=0.01"
      "accept-encoding"="gzip, deflate, br"
      "accept-language"="en-US,en;q=0.9"
      "Origin"=$MyLGEKU_Server
      "Referer"="$MyLGEKU_Server/cs/doSwitch.sap"
      "x-requested-with"="XMLHttpRequest"
    } -Body "xsrfid=$xsrfid"

    #Loop until a valid KU account is selected
    while($True){
        $KU_Accounts | select @{l=" # ";e={$_.index}},@{l="Account #";e={$_.accountNo}},@{l="Name";e={$_.partnerName}}, `
        @{l="Address";e={"$($_.premiseAddress.houseNo) $($_.premiseAddress.street) $($_.premiseAddress.unit), $($_.premiseAddress.city), $($_.premiseAddress.state) $($_.premiseAddress.zip)"}},@{l="Status";e={$_.status}} | format-table

        Write-Host "Please select a KU account: " -ForegroundColor Cyan -NoNewline
        $Global:KU_Accounts_Num = Read-Host

        if(-not ($KU_Accounts.Index.Contains([int]$KU_Accounts_Num))){
            Write-Host "`n'$KU_Accounts_Num' is an invalid selection! Please try again!`n" -ForegroundColor Red
            continue
        }else{
            break
        }
    }

    #Switch to the KU account chosen above
    $wr3 = Invoke-WebRequest -UseBasicParsing -Uri "$MyLGEKU_Server/cs/accswitch.sap" -Method "POST" -WebSession $KUMyMeter_Session -Headers @{
    "Accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
      "Accept-Encoding"="gzip, deflate, br"
      "Accept-Language"="en-US,en;q=0.9"
      "Origin"=$MyLGEKU_Server
      "Referer"="$MyLGEKU_Server/cs/doSwitch.sap"
    } -ContentType "application/x-www-form-urlencoded" -Body "xsrfid=$xsrfid&accselect=$KU_Accounts_Num&as_sfid=$as_sfid&as_fid=$as_fid"
    
    #Pull KU
    $wr4 = Invoke-WebRequest "$MyLGEKU_Server/cs/doStart.sap" -WebSession $KUMyMeter_Session

    #Gather required parameters from the KU website to authenticate to the MyMeter application
    $wr5 = Invoke-RestMethod "$MyLGEKU_Server/cs/b.ee_ams_mymeter.sap" -WebSession $KUMyMeter_Session
    $MyMeterAuthURL = ($wr5 | Select-String -Pattern "action=""(.*)"" ").Matches.Groups[1].value
    #$xsrfid2 = [System.Net.WebUtility]::UrlEncode($(($wr5 | Select-String -Pattern "name=""xsrfid"" value=""(.*)""/").Matches.Groups[1].value))
    #$as_sfid2 = [System.Net.WebUtility]::UrlEncode($(($wr5 | Select-String -Pattern "name=""as_sfid"" value=""(.*)"" /><input").Matches.Groups[1].value))
    #$as_fid2 = [System.Net.WebUtility]::UrlEncode($(($wr5 | Select-String -Pattern "name=""as_fid"" value=""(.*)"" /").Matches.Groups[1].value))
    #$JSONRequest = $wr5.Substring($wr5.IndexOf("JSON.stringify")+15)
    #$JSONRequest = $JSONRequest.Substring(0,$JSONRequest.IndexOf("})")+1)
    #$JSONRequest = [System.Net.WebUtility]::UrlEncode($($JSONRequest | ConvertFrom-Json | ConvertTo-Json -Compress))

    $xsrfid = ($wr5 | Select-String -Pattern "name=""xsrfid"" value=""(.*)""/").Matches.Groups[1].value
    $as_sfid = ($wr5 | Select-String -Pattern "name=""as_sfid"" value=""(.*)"" /><input").Matches.Groups[1].value
    $as_fid = ($wr5 | Select-String -Pattern "name=""as_fid"" value=""(.*)"" /").Matches.Groups[1].value
    $JSONRequest = $wr5.Substring($wr5.IndexOf("JSON.stringify")+15)
    $JSONRequest = $JSONRequest.Substring(0,$JSONRequest.IndexOf("})")+1)
    $JSONRequest = $JSONRequest | ConvertFrom-Json
    $wr6Request = [Ordered]@{
        'xsrfid' = $xsrfid
        'request' = ($JSONRequest | ConvertTo-Json -Compress)
        'as_sfid' = $as_sfid
        'as_fid2' = $as_fid
    }

    #"xsrfid=$xsrfid2&request=$JSONRequest&as_sfid=$as_sfid2&as_fid=$as_fid2"

    #Authenticate to MyMeter via the external authentication URL pulled from KU above
    #$wr6 = Invoke-WebRequest -UseBasicParsing -Uri $MyMeterAuthURL -WebSession $KUMyMeter_Session -Method Post -ContentType "application/x-www-form-urlencoded" -Body "xsrfid=$xsrfid2&request=$JSONRequest&as_sfid=$as_sfid2&as_fid=$as_fid2"
    $wr6 = Invoke-WebRequest -UseBasicParsing -Uri $MyMeterAuthURL -WebSession $KUMyMeter_Session -Method Post -ContentType "application/x-www-form-urlencoded" -Body $wr6Request
    $wr7 = Invoke-WebRequest -UseBasicParsing -Uri $KUMyMeter_Server -WebSession $KUMyMeter_Session
    $wr8 = Invoke-WebRequest -UseBasicParsing -Uri "$KUMyMeter_Server/Dashboard" -WebSession $KUMyMeter_Session

    $MyMeterPage = New-Object -ComObject "HTMLFile"
    $MyMeterPage.IHTMLDocument2_write($wr8.Content)
    $MyMeterAccountDetails = ($MyMeterPage.getElementsByTagName("div") | where {$_.className -match "col " -and $_.innerText -match "\n"}).innerText.Trim()

    Write-Host "MyMeter login success!" -ForegroundColor Green
    Write-Host "`nMyMeter account details:" -ForegroundColor Cyan
    Write-Host "$MyMeterAccountDetails`n"

    $Script:RequestVerificationToken = ($wr8.Content | Select-String -Pattern "name=""__RequestVerificationToken"".*value=""(.*)"" /").Matches.Groups[1].Value
}

function Get-KUMyMeterAccessLog{
param([switch]$GetMoreRows)
    if(!$KUMyMeter_UserInformation){
        $Global:KUMyMeter_UserInformation = (New-KUMyMeterWebRequest -Endpoint "/User/Information").Content
    }

    $KUMyMeter_HTMLOb = New-Object -ComObject "HTMLFile"
    $KUMyMeter_HTMLOb.IHTMLDocument2_write($KUMyMeter_UserInformation)
    $KUMyMeter_RequestVerificationToken = ($KUMyMeter_HTMLOb.getElementsByTagName("input") | where {$_.name -eq "__RequestVerificationToken"})[0].value

    if($GetMoreRows.IsPresent){
        if($KUMyMeterAccessLogRowCount){$KUMyMeterAccessLogRowCount += 15}else{$Global:KUMyMeterAccessLogRowCount = 15}
       Write-Host "Retrieving $KUMyMeterAccessLogRowCount access log records..." -ForegroundColor Yellow
       $KUMyMeter_UserInformation = (New-KUMyMeterWebRequest -Endpoint "/User/LoadMoreActivities" -Method Post -Headers @{"x-requested-with"="XMLHttpRequest"} -ContentType "application/x-www-form-urlencoded; charset=UTF-8" -Body "rowCount=$KUMyMeterAccessLogRowCount&__RequestVerificationToken=$KUMyMeter_RequestVerificationToken" -REST).AjaxResults[0].Value
       $KUMyMeter_HTMLOb = New-Object -ComObject "HTMLFile"
       $KUMyMeter_HTMLOb.IHTMLDocument2_write($KUMyMeter_UserInformation)
    }

    $KUMyMeter_AccessLogTable = ($KUMyMeter_HTMLOb.getElementsByTagName("h4") | where {$_.innerText -match "Access Log"}).parentElement.getElementsByTagName("table")[0]

    $KUMyMeter_AccessLogHeaders = $KUMyMeter_AccessLogTable.getElementsByTagName("th") | foreach {$_.innerText}

    $KUMyMeter_AccessLogRows = $KUMyMeter_AccessLogTable.getElementsByTagName("tr")

    $KUMyMeter_AccessLogDataObject = [pscustomobject]@{}
    $KUMyMeter_AccessLogHeaders | foreach {$KUMyMeter_AccessLogDataObject | Add-Member -MemberType NoteProperty -Name $_ -Value ""}

    $KUMyMeter_AccessLogData = @()
    $KUMyMeter_AccessLogRows | foreach {$rows=$_.getElementsByTagName("td");$i=0;$KUMyMeter_AccessLogEntry=$KUMyMeter_AccessLogDataObject.psobject.Copy();$rows | foreach {$KUMyMeter_AccessLogEntry.$($KUMyMeter_AccessLogHeaders[$i]) = $($_.innerText);$i++};if($rows.length -ne 0 -and $KUMyMeter_AccessLogEntry.User -notmatch "View More"){$KUMyMeter_AccessLogData += $KUMyMeter_AccessLogEntry}}

    return $KUMyMeter_AccessLogData
}

function Get-KUMyMeterAdditionalUsers{
    if(!$KUMyMeter_UserInformation){
        $Global:KUMyMeter_UserInformation = (New-KUMyMeterWebRequest -Endpoint "/User/Information").Content
    }

    $KUMyMeter_HTMLOb = New-Object -ComObject "HTMLFile"
    $KUMyMeter_HTMLOb.IHTMLDocument2_write($KUMyMeter_UserInformation)
    $KUMyMeter_RequestVerificationToken = ($KUMyMeter_HTMLOb.getElementsByTagName("input") | where {$_.name -eq "__RequestVerificationToken"})[0].value

    #$KUMyMeter_TableSections = $KUMyMeter_HTMLOb.getElementsByTagName("h4") | where {$_.innerText -match "Registered Users|Additional User Access|Access Log"} | foreach {$_.parentElement}

    try{
        $KUMyMeter_AdditionalUsersTable = ($KUMyMeter_HTMLOb.getElementsByTagName("h4") | where {$_.innerText -match "Additional User Access"}).parentElement.getElementsByTagName("table")[0]
        if($KUMyMeter_AdditionalUsersTable -eq $null){write-host "No additional user access exists!";return}
    }catch{
        write-host "No additional user access exists!"
        return
    }

    $KUMyMeter_AdditionalUsersHeaders = $KUMyMeter_AdditionalUsersTable.getElementsByTagName("th") | foreach {$_.innerText}

    $KUMyMeter_AdditionalUsersRows = $KUMyMeter_AdditionalUsersTable.getElementsByTagName("tr")

    $KUMyMeter_AdditionalUserDataObject = [pscustomobject]@{}
    $KUMyMeter_AdditionalUsersHeaders | foreach {$KUMyMeter_AdditionalUserDataObject | Add-Member -MemberType NoteProperty -Name $_ -Value ""}

    $KUMyMeter_AdditionalUsersData = @()
    $KUMyMeter_AdditionalUsersRows | foreach {$rows=$_.getElementsByTagName("td");$i=0;$KUMyMeter_AdditionalUser=$KUMyMeter_AdditionalUserDataObject.psobject.Copy();$rows | foreach {$KUMyMeter_AdditionalUser.$($KUMyMeter_AdditionalUsersHeaders[$i]) = $($_.innerText);$i++};if($rows.length -ne 0){$KUMyMeter_AdditionalUsersData += $KUMyMeter_AdditionalUser}}

    return $KUMyMeter_AdditionalUsersData
}

function Get-KUMyMeterBillingHistory{
    $KUMyMeter_ManageAccounts = (New-KUMyMeterWebRequest -Endpoint "/ManageAccounts").Content
    $KUMyMeter_HTMLOb = New-Object -ComObject "HTMLFile"
    $KUMyMeter_HTMLOb.IHTMLDocument2_write($KUMyMeter_ManageAccounts)
    $KUMyMeter_RequestVerificationToken = ($KUMyMeter_HTMLOb.getElementsByTagName("input") | where {$_.name -eq "__RequestVerificationToken"})[0].value

    $KUMyMeter_Billing = (New-KUMyMeterWebRequest -Endpoint "/ManageAccounts/Transactions" -Method Post -Headers @{"x-requested-with"="XMLHttpRequest"} -ContentType "application/x-www-form-urlencoded; charset=UTF-8" `
    -Body "accountNumber=$($KU_Accounts[$KU_Accounts_Num].accountNo)&__RequestVerificationToken=$KUMyMeter_RequestVerificationToken" -REST).AjaxResults[0].Value

    $KUMyMeter_HTMLOb = New-Object -ComObject "HTMLFile"
    $KUMyMeter_HTMLOb.IHTMLDocument2_write($KUMyMeter_Billing)

    try{
        $KUMyMeter_BillingTable = $KUMyMeter_HTMLOb.getElementsByTagName("table")[0]
        if($KUMyMeter_BillingTable -eq $null){write-host "No account billing history exists!";return}
    }catch{
        write-host "No account billing history exists!"
        return
    }

    $KUMyMeter_BillingTable_Headers = $KUMyMeter_BillingTable.getElementsByTagName("th") | foreach {$_.innerText}
    $KUMyMeter_BillingTable_Rows = $KUMyMeter_BillingTable.getElementsByTagName("tr")

    $KUMyMeter_BillingDataObject = [pscustomobject]@{}
    $KUMyMeter_BillingTable_Headers | foreach {$KUMyMeter_BillingDataObject | Add-Member -MemberType NoteProperty -Name $_ -Value ""}

    $KUMyMeter_BillingData = @()
    $KUMyMeter_BillingTable_Rows | foreach {$rows=$_.getElementsByTagName("td");$i=0;$KUMyMeter_BillingDatum=$KUMyMeter_BillingDataObject.psobject.Copy();$rows | foreach {$KUMyMeter_BillingDatum.$($KUMyMeter_BillingTable_Headers[$i]) = $($_.innerText);$i++};if($rows.length -ne 0 -and $KUMyMeter_BillingDatum.User -notmatch "View More"){$KUMyMeter_BillingData += $KUMyMeter_BillingDatum}}
    
    return $KUMyMeter_BillingData
}

function Get-KUMyMeterRegisteredUsers{
    if(!$KUMyMeter_UserInformation){
        $Global:KUMyMeter_UserInformation = (New-KUMyMeterWebRequest -Endpoint "/User/Information").Content
    }

    $KUMyMeter_HTMLOb = New-Object -ComObject "HTMLFile"
    $KUMyMeter_HTMLOb.IHTMLDocument2_write($KUMyMeter_UserInformation)
    $KUMyMeter_RequestVerificationToken = ($KUMyMeter_HTMLOb.getElementsByTagName("input") | where {$_.name -eq "__RequestVerificationToken"})[0].value

    #$KUMyMeter_TableSections = $KUMyMeter_HTMLOb.getElementsByTagName("h4") | where {$_.innerText -match "Registered Users|Additional User Access|Access Log"} | foreach {$_.parentElement}

    $KUMyMeter_RegisteredUsersTable = ($KUMyMeter_HTMLOb.getElementsByTagName("h4") | where {$_.innerText -match "Registered Users"}).parentElement.getElementsByTagName("table")[0]

    $KUMyMeter_RegisteredUsersHeaders = $KUMyMeter_RegisteredUsersTable.getElementsByTagName("th") | foreach {$_.innerText}

    $KUMyMeter_RegisteredUsersRows = $KUMyMeter_RegisteredUsersTable.getElementsByTagName("tr")

    $KUMyMeter_RegisteredUserDataObject = [pscustomobject]@{}
    $KUMyMeter_RegisteredUsersHeaders | foreach {$KUMyMeter_RegisteredUserDataObject | Add-Member -MemberType NoteProperty -Name $_ -Value ""}

    $KUMyMeter_RegisteredUsersData = @()
    $KUMyMeter_RegisteredUsersRows | foreach {$rows=$_.getElementsByTagName("td");$i=0;$KUMyMeter_RegisteredUser=$KUMyMeter_RegisteredUserDataObject.psobject.Copy();$rows | foreach {$KUMyMeter_RegisteredUser.$($KUMyMeter_RegisteredUsersHeaders[$i]) = $($_.innerText);$i++};if($rows.length -ne 0){$KUMyMeter_RegisteredUsersData += $KUMyMeter_RegisteredUser}}

    return $KUMyMeter_RegisteredUsersData
}

function Get-KUMyMeterMeters{
    #Generate current timestamp (Unix epoch) and request usage statistics from MyMeter
    $timestamp = (get-date -UFormat "%s") -replace "\."
    $timestamp = $timestamp.Substring(0,$timestamp.Length-2)
    $DataSource = (New-KUMyMeterWebRequest -Endpoint "/Dashboard/Table?_=$timestamp" -Headers @{"x-requested-with"="XMLHttpRequest"} -REST).AjaxResults[0].Value

    #Find MyMeter Display Meter elements and parse out data
    $DisplayMetersStart = $DataSource.indexof("aria-label=""Display Meter""")
    $DisplayMetersStop = $DataSource.indexof("</select>",$DisplayMetersStart)
    $DisplayMetersStr = $DataSource.Substring($DisplayMetersStart,$DisplayMetersStop-$DisplayMetersStart)
    $AllDisplayMeters = $DisplayMetersStr -Split "<option "
    $AllDisplayMeters = $AllDisplayMeters[1..($AllDisplayMeters.Length-1)]
    
    #Pull out Meter names and values, store into an ordered Hash Table
    $AllDisplayMetersNames = (($AllDisplayMeters | Select-String -Pattern "value=""(.*)"">(.*)<").Matches.Groups | where {$_.Name -eq "2"}).Value
    $AllDisplayMetersValues = (($AllDisplayMeters | Select-String -Pattern "value=""(.*)"">(.*)<").Matches.Groups | where {$_.Name -eq "1"}).Value
    $AllDisplayMeters = [ordered]@{}
    for($i=0;$i -lt $AllDisplayMetersNames.Length;$i++){
        $AllDisplayMeters.Add($AllDisplayMetersNames[$i],$AllDisplayMetersValues[$i])
    }

    $Script:KUMyMeter_Meters = $AllDisplayMeters
    return $AllDisplayMeters
}

function Get-KUMyMeterUsage{
    #Generate current timestamp (Unix epoch) and request usage statistics from MyMeter table
    $timestamp = (get-date -UFormat "%s") -replace "\."
    $timestamp = $timestamp.Substring(0,$timestamp.Length-2)
    $DataSource = (New-KUMyMeterWebRequest -Endpoint "/Dashboard/Table?_=$timestamp" -Headers @{"x-requested-with"="XMLHttpRequest"} -REST).AjaxResults[0].Value

    $DataSource1 = $DataSource.Substring($DataSource.indexof("""dataSource"": [")+14)
    $DataSource2 = $DataSource1.Substring(0,$DataSource1.IndexOf("}]")+2)
    $MeterData = ($DataSource2 | ConvertFrom-Json) | select @{l="Time";e={$_.rowid}},@{l="Date";e={$_.columnid}},@{l="Cost";e={$_.value}}
    return $MeterData
}

function Get-KUMyMeterUsageAdvanced{
param(
$DisplayMeter = "All Usage", #Default to All Usage
[ValidateSet("FifteenMinByDay","ThirtyMinByDay","HourByDay","DayByWeek","DayByMonth","MonthByYear")]
$UsageRange = "FifteenMinByDay",
[ValidateSet("Consumption(kWh)","Dollar($)")]
$UsageType = "Dollar($)"
)

    $KUMyMeter_SelectedUsageRange = @(
        "FifteenMinByDay"
        "ThirtyMinByDay"
        "HourByDay"
        "DayByWeek"
        "DayByMonth"
        "MonthByYear"
    )

    $KUMyMeter_SelectedUsageType = @{
        "Consumption(kWh)" = 1
        "Dollar($)" = 3
    }

    $KUMyMeter_Display = @{
        "All Meters" = -1
        "All Usage" = -2
    }

    $UsageTypeValue = $KUMyMeter_SelectedUsageType[$UsageType]

    if($DisplayMeter -match "All Usage|All Meters"){
        $DisplayMeter = $KUMyMeter_Display[$DisplayMeter]
    }else{
        if($KUMyMeter_Meters){
            if($KUMyMeter_Meters.Keys -contains $DisplayMeter){
                $DisplayMeter = $KUMyMeter_Meters[$DisplayMeter]
            }elseif(-not ($KUMyMeter_Meters.Values -contains $DisplayMeter)){
                while($True){
                    Write-Host "`n**********All Available KU Display Meters**********" -ForegroundColor Green
                    $i=0;$AllDisplayMeters.Keys | foreach {Write-Host "$i - $_";$i++}
                    Write-Host "`nPlease select a KU Display Meter #: " -NoNewline -ForegroundColor Cyan
                    $x = [int](Read-Host)
                    if($x -lt $KUMyMeter_Meters.Keys.Count -and $x -ge 0){
                        $DisplayMeter = $KUMyMeter_Meters[$x]
                        break
                    }else{
                        Write-Host "'$x' is not a valid selection. Try again!`n" -ForegroundColor Red
                        continue
                    }
                }
            }
        }else{
            Get-KUMyMeterMeters | Out-Null
            if($KUMyMeter_Meters.Keys -contains $DisplayMeter){
                $DisplayMeter = $KUMyMeter_Meters[$DisplayMeter]
            }elseif(-not ($KUMyMeter_Meters.Values -contains $DisplayMeter)){
                while($True){
                    Write-Host "`n**********All Available KU Display Meters**********" -ForegroundColor Green
                    $i=0;$AllDisplayMeters.Keys | foreach {Write-Host "$i - $_";$i++}
                    Write-Host "`nPlease select a KU Display Meter #: " -NoNewline -ForegroundColor Cyan
                    $x = [int](Read-Host)
                    if($x -lt $KUMyMeter_Meters.Keys.Count -and $x -ge 0){
                        $DisplayMeter = $KUMyMeter_Meters[$x]
                        break
                    }else{
                        Write-Host "'$x' is not a valid selection. Try again!`n" -ForegroundColor Red
                        continue
                    }
                }
            }
        }
    }

    $DataSource = (New-KUMyMeterWebRequest -Endpoint "/Dashboard/Table" -Method Post -Headers @{"x-requested-with"="XMLHttpRequest"} -ContentType "application/x-www-form-urlencoded; charset=UTF-8" `
    -Body "SelectedUsageRange=$UsageRange&Display=$DisplayMeter&SelectedUsageType=$UsageTypeValue&__RequestVerificationToken=$RequestVerificationToken" -REST).AjaxResults[0].Value

    <#
    $wr10 = Invoke-WebRequest -UseBasicParsing -Uri "$KUMyMeter_Server/Dashboard/Table" `
    -Method "POST" `
    -WebSession $KUMyMeter_Session `
    -Headers @{
    "authority"="mymeter.lge-ku.com"
      "method"="POST"
      "path"="/Dashboard/Table"
      "scheme"="https"
      "accept"="text/plain, */*; q=0.01"
      "accept-encoding"="gzip, deflate, br"
      "accept-language"="en-US,en;q=0.9"
      "origin"=$KUMyMeter_Server
      "referer"="$KUMyMeter_Server/Dashboard"
      "x-requested-with"="XMLHttpRequest"
    } `
    -ContentType "application/x-www-form-urlencoded; charset=UTF-8" `
    -Body "SelectedUsageRange=$UsageRange&Display=$DisplayMeter&SelectedUsageType=$UsageTypeValue&__RequestVerificationToken=$RequestVerificationToken"
    #>

    #$DataSource = ($wr10.Content | ConvertFrom-Json)
    #$DataSource1 = $DataSource.AjaxResults[0].Value.Substring($DataSource.AjaxResults[0].Value.indexof("""dataSource"": [")+14)
    
    $DataSource1 = $DataSource.Substring($DataSource.indexof("""dataSource"": [")+14)
    $DataSource2 = $DataSource1.Substring(0,$DataSource1.IndexOf("}]")+2)
    
    if($UsageType -eq "Dollar($)"){
        $MeterData = ($DataSource2 | ConvertFrom-Json) | select @{l="Time";e={$_.rowid}},@{l="Date";e={$_.columnid}},@{l="Cost($)";e={$_.value}}
    }else{
        $MeterData = ($DataSource2 | ConvertFrom-Json) | select @{l="Time";e={$_.rowid}},@{l="Date";e={$_.columnid}},@{l="Consumption(kWh)";e={$_.value}}
    }

    return $MeterData
}

function New-KUMyMeterWebRequest{
param(
    $Endpoint="",
    [ValidateSet("Get","Post")]$Method="Get",
    $Headers=@{},
    $ContentType,
    $Body="",
    [switch]$REST
)
    if (!$KUMyMeter_Session){Connect-KUMyMeter}

    for($Retry=1;$Retry -le 3;$Retry++){
        try{
            if($REST.IsPresent){
                if($Body -ne $null -and $Body -ne ""){
                    $KUMyMeter_WR = Invoke-RestMethod -UseBasicParsing "$KUMyMeter_Server$Endpoint" -WebSession $KUMyMeter_Session `
                    -Headers $Headers -Method $Method -ContentType $ContentType -Body $Body
                }else{
                    $KUMyMeter_WR = Invoke-RestMethod -UseBasicParsing "$KUMyMeter_Server$Endpoint" -WebSession $KUMyMeter_Session `
                    -Headers $Headers -Method $Method
                }
            }else{
                if($Body -ne $null -and $Body -ne ""){
                    $KUMyMeter_WR = Invoke-WebRequest -UseBasicParsing "$KUMyMeter_Server$Endpoint" -WebSession $KUMyMeter_Session `
                    -Headers $Headers -Method $Method -ContentType $ContentType -Body $Body
                }else{
                    $KUMyMeter_WR = Invoke-WebRequest -UseBasicParsing "$KUMyMeter_Server$Endpoint" -WebSession $KUMyMeter_Session `
                    -Headers $Headers -Method $Method
                }
            }
            return $KUMyMeter_WR
        }catch{
            if($Retry -eq 3){
                Write-Host "Failed to submit web request 3 times in a row...Try again?(y/n): " -ForegroundColor Red -NoNewline
                $resp = Read-Host
                if($resp.ToLower() -match "y|yes"){$Retry=0}else{return}
            }else{
                Write-Host "Error occured while submitting web request to KU MyMeter! Retrying..." -ForegroundColor Yellow
                Start-Sleep -Seconds 2
            }
        }
    }
}

Export-ModuleMember -Function Connect-KUMyMeter,Get-KUMyMeterAccessLog,Get-KUMyMeterAdditionalUsers,Get-KUMyMeterBillingHistory,Get-KUMyMeterRegisteredUsers,Get-KUMyMeterMeters,Get-KUMyMeterUsage,Get-KUMyMeterUsageAdvanced,New-KUMyMeterWebRequest