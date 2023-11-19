$ProgressPreference = "SilentlyContinue"

<#   ***EXAMPLE USAGE***
Connect-KUMyMeter -Username "UserHere" -Password "PassHere"

$Meters = Get-KUMyMeterMeters

$MeterData = Get-KUMyMeterUsage

$MeterData = Get-KUMyMeterUsageAdvanced -DisplayMeter "All Usage" -UsageRange = "FifteenMinByDay" -UsageType = "Dollar($)"
#>

function Connect-KUMyMeter{
param($Username,$Password)
    $Global:MyLGEKU_Server = "https://lge-ku.com"
    $Global:KUMyMeter_Server = "https://mymeter.lge-ku.com"
    #Verify site is reachable and retrieve Form ID + Form Token required for login request
    try{
        $wr = Invoke-RestMethod $MyLGEKU_Server -UseBasicParsing -SessionVariable Global:KUMyMeter_Session
        $FormBuildID = ($wr | Select-String -Pattern "name=""form_build_id"" value=""(.*)"" ").Matches.Groups[1].value
        $FormToken = ($wr | Select-String -Pattern "name=""form_token"" value=""(.*)"" ").Matches.Groups[1].value
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
            $Password = $Creds.GetNetworkCredential().Password
        }elseif(-not ($Username -and $Password) -or $LoginFailure){
            $LoginFailure = $False
            $Creds = Get-Credential -Message "Please enter your KU credentials"
            $Username = $Creds.GetNetworkCredential().UserName
            $Password = $Creds.GetNetworkCredential().Password
        }

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
            $wr1 = Invoke-WebRequest -UseBasicParsing -Uri "$MyLGEKU_Server/cs/logon.sap" -Method "POST" -WebSession $KUMyMeter_Session -ContentType "application/x-www-form-urlencoded" -Body $KUMyMeter_Login_Data
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
    $KUAccounts = Invoke-RestMethod "$MyLGEKU_Server/cs/getAcctListAjax.ajax" -WebSession $KUMyMeter_Session -Method Post -ContentType "application/x-www-form-urlencoded; charset=UTF-8" -Headers @{
      "accept"="application/json, text/javascript, */*; q=0.01"
      "accept-encoding"="gzip, deflate, br"
      "accept-language"="en-US,en;q=0.9"
      "Origin"=$MyLGEKU_Server
      "Referer"="$MyLGEKU_Server/cs/doSwitch.sap"
      "x-requested-with"="XMLHttpRequest"
    } -Body "xsrfid=$xsrfid"

    #Loop until a valid KU account is selected
    while($True){
        $KUAccounts | select @{l=" # ";e={$_.index}},@{l="Account #";e={$_.accountNo}},@{l="Name";e={$_.partnerName}}, `
        @{l="Address";e={"$($_.premiseAddress.houseNo) $($_.premiseAddress.street) $($_.premiseAddress.unit), $($_.premiseAddress.city), $($_.premiseAddress.state) $($_.premiseAddress.zip)"}},@{l="Status";e={$_.status}} | format-table

        Write-Host "Please select a KU account: " -ForegroundColor Cyan -NoNewline
        $AccNum = Read-Host

        if(-not ($KUAccounts.Index.Contains([int]$AccNum))){
            Write-Host "`n'$AccNum' is an invalid selection! Please try again!`n" -ForegroundColor Red
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
    } -ContentType "application/x-www-form-urlencoded" -Body "xsrfid=$xsrfid&accselect=$AccNum&as_sfid=$as_sfid&as_fid=$as_fid"
    
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

function Get-KUMyMeterRegisteredUsers{
    $KUMyMeter_UserInformation = Invoke-RestMethod "$KUMyMeter_Server/User/Information"
}

function Get-KUMyMeterMeters{
    #Generate current timestamp (Unix epoch) and request usage statistics from MyMeter
    $timestamp = (get-date -UFormat "%s") -replace "\."
    $timestamp = $timestamp.Substring(0,$timestamp.Length-2)
    $wr9 = Invoke-WebRequest -UseBasicParsing -Uri "$KUMyMeter_Server/Dashboard/Table?_=$timestamp" -WebSession $KUMyMeter_Session -Headers @{
    "authority"="mymeter.lge-ku.com"
      "method"="GET"
      "path"="/Dashboard/Table?_=$timestamp"
      "scheme"="https"
      "accept"="text/plain, */*; q=0.01"
      "accept-encoding"="gzip, deflate, br"
      "accept-language"="en-US,en;q=0.9"
      "x-requested-with"="XMLHttpRequest"
    }

    #Convert Ajax web request above from a JSON string to a JSON object
    #Then, parse out DataSource and convert to JSON object
    $DataSource = ($wr9.Content | ConvertFrom-Json)
    $DataSource = $DataSource.AjaxResults[0].Value

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
    $wr9 = Invoke-WebRequest -UseBasicParsing -Uri "$KUMyMeter_Server/Dashboard/Table?_=$timestamp" -WebSession $KUMyMeter_Session -Headers @{
    "authority"="mymeter.lge-ku.com"
      "method"="GET"
      "path"="/Dashboard/Table?_=$timestamp"
      "scheme"="https"
      "accept"="text/plain, */*; q=0.01"
      "accept-encoding"="gzip, deflate, br"
      "accept-language"="en-US,en;q=0.9"
      "x-requested-with"="XMLHttpRequest"
    }

    #Convert Ajax web request above from a JSON string to a JSON object
    #Then, parse out DataSource and convert to JSON object
    $DataSource = ($wr9.Content | ConvertFrom-Json)
    $DataSource1 = $DataSource.AjaxResults[0].Value.Substring($DataSource.AjaxResults[0].Value.indexof("""dataSource"": [")+14)
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
            if($KUMyMeterMeters.Keys -contains $DisplayMeter){
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
            if($KUMyMeterMeters.Keys -contains $DisplayMeter){
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

    $DataSource = ($wr10.Content | ConvertFrom-Json)
    $DataSource1 = $DataSource.AjaxResults[0].Value.Substring($DataSource.AjaxResults[0].Value.indexof("""dataSource"": [")+14)
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
    $Endpoint,
    [ValidateSet("Get","Post")]$Method="Get",
    $ContentType="",
    $Body,
    [switch]$REST
)
    if (!$KUMyMeter_Session){Connect-KUMyMeter}

    for($Retry=1;$Retry -le 3;$Retry++){
        try{
            if($REST.IsPresent){
                if($Body -ne $null -and $Body -ne ""){
                    $ServiceNow_WR = Invoke-RestMethod -UseBasicParsing "https://$ServiceNow_Server$Endpoint" -WebSession $ServiceNow_Session `
                    -Method $Method -ContentType $ContentType -Body $Body
                }else{
                    $ServiceNow_WR = Invoke-RestMethod -UseBasicParsing "https://$ServiceNow_Server$Endpoint" -WebSession $ServiceNow_Session `
                    -Method $Method
                }
            }else{
                if($Body -ne $null -and $Body -ne ""){
                    $ServiceNow_WR = Invoke-WebRequest -UseBasicParsing "https://$ServiceNow_Server$Endpoint" -WebSession $ServiceNow_Session `
                    -Method $Method -ContentType $ContentType -Body $Body
                }else{
                    $ServiceNow_WR = Invoke-WebRequest -UseBasicParsing "https://$ServiceNow_Server$Endpoint" -WebSession $ServiceNow_Session `
                    -Method $Method
                }
            }
            return $ServiceNow_WR
        }catch{
            if($Retry -eq 3){
                Write-Host "Failed to submit web request 3 times in a row...Try again?(y/n): " -ForegroundColor Red -NoNewline
                $resp = Read-Host
                if($resp.ToLower() -match "y|yes"){$Retry=0}else{return}
            }else{
                Write-Host "Error occured while submitting web request to SNOW! Retrying..." -ForegroundColor Yellow
                Start-Sleep -Seconds 2
            }
        }
    }
}