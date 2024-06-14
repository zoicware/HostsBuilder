If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}


<#links
repo: https://github.com/hagezi/dns-blocklists

Threat Intelligence Feeds
 https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/tif.txt

 Multi PRO - Extended protection
https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt

#steven black hosts
https://github.com/StevenBlack/hosts/blob/master/data/StevenBlack/hosts


#>

function Global:Get-FileFromWeb {
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        [string]$URL,
  
        # Parameter help description
        [Parameter(Mandatory)]
        [string]$File 
    )
    Begin {
        function Show-Progress {
            param (
                # Enter total value
                [Parameter(Mandatory)]
                [Single]$TotalValue,
        
                # Enter current value
                [Parameter(Mandatory)]
                [Single]$CurrentValue,
        
                # Enter custom progresstext
                [Parameter(Mandatory)]
                [string]$ProgressText,
        
                # Enter value suffix
                [Parameter()]
                [string]$ValueSuffix,
        
                # Enter bar lengh suffix
                [Parameter()]
                [int]$BarSize = 40,

                # show complete bar
                [Parameter()]
                [switch]$Complete
            )
            
            # calc %
            $percent = $CurrentValue / $TotalValue
            $percentComplete = $percent * 100
            if ($ValueSuffix) {
                $ValueSuffix = " $ValueSuffix" # add space in front
            }
            if ($psISE) {
                Write-Progress "$ProgressText $CurrentValue$ValueSuffix of $TotalValue$ValueSuffix" -id 0 -percentComplete $percentComplete            
            }
            else {
                # build progressbar with string function
                $curBarSize = $BarSize * $percent
                $progbar = ''
                $progbar = $progbar.PadRight($curBarSize, [char]9608)
                $progbar = $progbar.PadRight($BarSize, [char]9617)
        
                if (!$Complete.IsPresent) {
                    Write-Host -NoNewLine "`r$ProgressText $progbar [ $($CurrentValue.ToString('#.###').PadLeft($TotalValue.ToString('#.###').Length))$ValueSuffix / $($TotalValue.ToString('#.###'))$ValueSuffix ] $($percentComplete.ToString('##0.00').PadLeft(6)) % complete"
                }
                else {
                    Write-Host -NoNewLine "`r$ProgressText $progbar [ $($TotalValue.ToString('#.###').PadLeft($TotalValue.ToString('#.###').Length))$ValueSuffix / $($TotalValue.ToString('#.###'))$ValueSuffix ] $($percentComplete.ToString('##0.00').PadLeft(6)) % complete"                    
                }                
            }   
        }
    }
    Process {
        try {
            $storeEAP = $ErrorActionPreference
            $ErrorActionPreference = 'Stop'
        
            # invoke request
            $request = [System.Net.HttpWebRequest]::Create($URL)
            $response = $request.GetResponse()
  
            if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403 -or $response.StatusCode -eq 404) {
                throw "Remote file either doesn't exist, is unauthorized, or is forbidden for '$URL'."
            }
  
            if ($File -match '^\.\\') {
                $File = Join-Path (Get-Location -PSProvider 'FileSystem') ($File -Split '^\.')[1]
            }
            
            if ($File -and !(Split-Path $File)) {
                $File = Join-Path (Get-Location -PSProvider 'FileSystem') $File
            }

            if ($File) {
                $fileDirectory = $([System.IO.Path]::GetDirectoryName($File))
                if (!(Test-Path($fileDirectory))) {
                    [System.IO.Directory]::CreateDirectory($fileDirectory) | Out-Null
                }
            }

            [long]$fullSize = $response.ContentLength
            $fullSizeMB = $fullSize / 1024 / 1024
  
            # define buffer
            [byte[]]$buffer = new-object byte[] 1048576
            [long]$total = [long]$count = 0
  
            # create reader / writer
            $reader = $response.GetResponseStream()
            $writer = new-object System.IO.FileStream $File, 'Create'
  
            # start download
            $finalBarCount = 0 #show final bar only one time
            do {
          
                $count = $reader.Read($buffer, 0, $buffer.Length)
          
                $writer.Write($buffer, 0, $count)
              
                $total += $count
                $totalMB = $total / 1024 / 1024
          
                if ($fullSize -gt 0) {
                    Show-Progress -TotalValue $fullSizeMB -CurrentValue $totalMB -ProgressText "Downloading $($File.Name)" -ValueSuffix 'MB'
                }

                if ($total -eq $fullSize -and $count -eq 0 -and $finalBarCount -eq 0) {
                    Show-Progress -TotalValue $fullSizeMB -CurrentValue $totalMB -ProgressText "Downloading $($File.Name)" -ValueSuffix 'MB' -Complete
                    $finalBarCount++
                    #Write-Host "$finalBarCount"
                }

            } while ($count -gt 0)
        }
  
        catch {
        
            $ExeptionMsg = $_.Exception.Message
            Write-Host "Download breaks with error : $ExeptionMsg"
        }
  
        finally {
            # cleanup
            if ($reader) { $reader.Close() }
            if ($writer) { $writer.Flush(); $writer.Close() }
        
            $ErrorActionPreference = $storeEAP
            [GC]::Collect()
        }    
    }
}











#------------------------------------------- GUI

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Hosts Builder'
$form.Size = New-Object System.Drawing.Size(420, 310)
$form.StartPosition = 'CenterScreen'
$form.BackColor = 'Black'

# Create the group box
$groupBox = New-Object System.Windows.Forms.GroupBox
$groupBox.Text = 'DNS Blocklists'
$groupBox.Size = New-Object System.Drawing.Size(385, 180)
$groupBox.Location = New-Object System.Drawing.Point(10, 10)
$groupBox.ForeColor = 'White' 
$groupBox.BackColor = 'Gray' 

# Create the checkboxes
$Global:checkBox1 = New-Object System.Windows.Forms.CheckBox
$checkBox1.Text = 'Threat Intelligence Feeds [hagezi]'
$checkBox1.Location = New-Object System.Drawing.Point(10, 20)
$checkBox1.Size = New-Object System.Drawing.Size(220, 20)

$Global:checkBox2 = New-Object System.Windows.Forms.CheckBox
$checkBox2.Text = 'Multi PRO [hagezi]'
$checkBox2.Location = New-Object System.Drawing.Point(10, 45)
$checkBox2.Size = New-Object System.Drawing.Size(180, 20)

$Global:checkBox3 = New-Object System.Windows.Forms.CheckBox
$checkBox3.Text = 'Steven Black Hosts'
$checkBox3.Location = New-Object System.Drawing.Point(10, 70)
$checkBox3.Size = New-Object System.Drawing.Size(180, 20)

$Global:checkBox4 = New-Object System.Windows.Forms.CheckBox
$checkBox4.Text = 'URL Haus Malware'
$checkBox4.Location = New-Object System.Drawing.Point(10, 95)
$checkBox4.Size = New-Object System.Drawing.Size(180, 20)

$Global:checkBox5 = New-Object System.Windows.Forms.CheckBox
$checkBox5.Text = 'Windows Telemetry'
$checkBox5.Location = New-Object System.Drawing.Point(10, 120)
$checkBox5.Size = New-Object System.Drawing.Size(180, 20)

$Global:checkBox6 = New-Object System.Windows.Forms.CheckBox
$checkBox6.Text = 'AdguardDNS'
$checkBox6.Location = New-Object System.Drawing.Point(10, 145)
$checkBox6.Size = New-Object System.Drawing.Size(180, 20)

# Add the checkboxes to the group box
$groupBox.Controls.Add($checkBox1)
$groupBox.Controls.Add($checkBox2)
$groupBox.Controls.Add($checkBox3)
$groupBox.Controls.Add($checkBox4)
$groupBox.Controls.Add($checkBox5)
$groupBox.Controls.Add($checkBox6)

# Create the Build Hosts button
$buildHostsButton = New-Object System.Windows.Forms.Button
$buildHostsButton.Text = 'Build Hosts'
$buildHostsButton.Size = New-Object System.Drawing.Size(95, 30)
$buildHostsButton.Location = New-Object System.Drawing.Point(10, 210)
$buildHostsButton.BackColor = 'Gray'
$buildHostsButton.ForeColor = 'White'
$buildHostsButton.Add_Click({
        $ProgressPreference = 'SilentlyContinue'

        Write-Host 'Building Hosts File...'

        #download hosts compression exe
        Invoke-WebRequest -uri 'https://github.com/zoicware/HostsBuilder/raw/main/compressHosts.exe' -OutFile "$env:temp\compressHosts.exe" -UseBasicParsing
        $paths = @()
        #use getfilefrom web for big lists
        if ($checkBox1.Checked) {
            #tif
            Get-FileFromWeb -URL 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/tif.txt' -File "$env:temp\tif.txt" 
            $paths += 'tif.txt'
        }
        if ($checkBox2.Checked) {
            #multi pro
            Get-FileFromWeb -URL 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt' -File "$env:temp\pro.txt" *>$null
            $paths += 'pro.txt'
        }
        if ($checkBox3.Checked) {
            #steven black
            Invoke-WebRequest -uri 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts' -OutFile "$env:temp\black.txt"
            $paths += 'black.txt'
        }
        if ($checkbox4.Checked) {
            #haus
            Invoke-WebRequest -Uri 'https://urlhaus.abuse.ch/downloads/hostfile' -UseBasicParsing -OutFile "$env:temp\haus.txt"
            #replace 127.0.0.1 with 0.0.0.0
            $content = Get-Content "$env:temp\haus.txt"
            $fixed = @()
            foreach ($line in $content) {
                if ($line -like '127.0.0.1*') {
                    $newLine = $line -replace '127.0.0.1' , '0.0.0.0'
                    $fixed += $newLine
                }
                else {
                    $fixed += $line
                }
            }
            set-content "$env:temp\fixedHaus.txt" -Value $fixed -Force
            Remove-Item "$env:temp\haus.txt" -Force -ErrorAction SilentlyContinue
            $paths += 'fixedHaus.txt'
        }
        if ($checkBox5.Checked) {
            #windows telemetry
            Invoke-WebRequest -uri 'https://raw.githubusercontent.com/zoicware/HostsBuilder/main/WindowsTelemetry.txt' -OutFile "$env:temp\WindowsTelemetry.txt" -UseBasicParsing
            $paths += 'WindowsTelemetry.txt'
        }
        if ($checkbox6.Checked) {
            #adguard
            Get-FileFromWeb -URL 'https://v.firebog.net/hosts/AdguardDNS.txt' -File "$env:temp\adguard.txt" *>$null
            $paths += 'adguard.txt'
        }

        
        #---------------------------------------- compress and compile
        Write-Host 'Compiling and Compressing Lists...'
        $i = 0
        foreach ($path in $paths) {
            $i++
            Start-Process "$env:temp\compressHosts.exe" -ArgumentList "-compression 1 -i `"$env:temp\$path`" -o $env:temp\$($path)Comp.txt" -WindowStyle Hidden -Wait
        }


        #combine into file
        $combinetxt = New-Item $env:temp\Combine.txt -Force
        foreach ($path in $paths) {
            $content = Get-Content "$env:TEMP\$($path)Comp.txt" 
            Add-Content $combinetxt.FullName -Value $content
        }

        #final compress
        $message = 'Replace Current Hosts File?'
        $caption = 'Replace Hosts'
        $buttons = [System.Windows.Forms.MessageBoxButtons]::YesNo
        $icon = [System.Windows.Forms.MessageBoxIcon]::Question
        $result = [System.Windows.Forms.MessageBox]::Show($message, $caption, $buttons, $icon)

        Write-Host 'Final Compression, this may take some time...'
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            Remove-Item "$env:SystemRoot\System32\drivers\etc\hosts" -Force
            Start-Process "$env:temp\compressHosts.exe" -ArgumentList "-compression 9 -i $($combinetxt.FullName) -o `"$env:SystemRoot\System32\drivers\etc\hosts`"" -Wait -WindowStyle Hidden
        }
        else {
            Start-Process "$env:temp\compressHosts.exe" -ArgumentList "-compression 9 -i $($combinetxt.FullName) -o `"$env:SystemRoot\System32\drivers\etc\hostsBuilder.txt`"" -Wait -WindowStyle Hidden
        }
       
        Write-host 'Done!'
        #cleanup
        
        foreach ($path in $paths) {
            Remove-Item "$env:temp\$path" -force -ErrorAction SilentlyContinue
            Remove-Item "$env:temp\$($path)Comp.txt" -force -ErrorAction SilentlyContinue
        }
        Remove-Item $combinetxt.FullName -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:temp\compressHosts.exe" -Force -ErrorAction SilentlyContinue
        
    })
$form.Controls.Add($buildHostsButton)


$clearDNS = New-Object System.Windows.Forms.Button
$clearDNS.Text = 'Flush DNS'
$clearDNS.Size = New-Object System.Drawing.Size(95, 30)
$clearDNS.Location = New-Object System.Drawing.Point(105, 210)
$clearDNS.BackColor = 'Gray'
$clearDNS.ForeColor = 'White'
$clearDNS.Add_Click({
        Write-Host 'Flushing DNS Cache...'
        ipconfig /flushdns >$null
        Write-Host 'Complete'
    })
$form.Controls.Add($clearDNS)

$backUpDNS = New-Object System.Windows.Forms.Button
$backUpDNS.Text = 'Backup Hosts'
$backUpDNS.Size = New-Object System.Drawing.Size(95, 30)
$backUpDNS.Location = New-Object System.Drawing.Point(200, 210)
$backUpDNS.BackColor = 'Gray'
$backUpDNS.ForeColor = 'White'
$backUpDNS.Add_Click({
        Write-Host 'Creating a backup of Current Hosts...'
        $hostsbak = "$env:SystemRoot\System32\drivers\etc\hosts.bak"
        $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
        #test if there is already a backup
        if (Test-Path -Path $hostsbak) {
            $message = 'A backup file already exists. Do you want to override it?'
            $caption = 'Confirm Override'
            $buttons = [System.Windows.Forms.MessageBoxButtons]::YesNo
            $icon = [System.Windows.Forms.MessageBoxIcon]::Question
            $result = [System.Windows.Forms.MessageBox]::Show($message, $caption, $buttons, $icon)
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                Copy-Item -Path $hosts -Destination $hostsbak -Force
            }
            else {
                #generate a random 3 digit number
                $randomNumber = Get-Random -Minimum 100 -Maximum 1000
                Copy-Item -Path $hosts -Destination "$env:SystemRoot\System32\drivers\etc\hosts$randomNumber.bak" 
            }
        }
        else {
            Copy-Item -Path $hosts -Destination $hostsbak
        }
        Write-Host 'Hosts Backups:'
        #get all hosts backups
        $backups = (Get-ChildItem -Path "$env:SystemRoot\System32\drivers\etc\" -Filter hosts*.bak).FullName
        foreach ($backup in $backups) {
            Write-Host "[$backup]" -ForegroundColor Yellow
        }
        
    })
$form.Controls.Add($backUpDNS)

$clearHosts = New-Object System.Windows.Forms.Button
$clearHosts.Text = 'Reset Hosts'
$clearHosts.Size = New-Object System.Drawing.Size(95, 30)
$clearHosts.Location = New-Object System.Drawing.Point(295, 210)
$clearHosts.BackColor = 'Gray'
$clearHosts.ForeColor = 'White'
$clearHosts.Add_Click({
        $defaultHosts = @'
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
'@
        $message = 'Are you sure you want to reset hosts back to default?'
        $caption = 'Confirm Reset'
        $buttons = [System.Windows.Forms.MessageBoxButtons]::YesNo
        $icon = [System.Windows.Forms.MessageBoxIcon]::Question
        $result = [System.Windows.Forms.MessageBox]::Show($message, $caption, $buttons, $icon)
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
            Remove-Item $hosts -Force
            Set-Content -Path $hosts -Value $defaultHosts -Force
            Write-Host 'Hosts File Reset'
        }
    })
$form.Controls.Add($clearHosts)

# Add the group box to the form
$form.Controls.Add($groupBox)

# Show the form
$form.ShowDialog() | Out-Null

