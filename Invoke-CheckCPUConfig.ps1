<#
   .SYNOPSIS
        Check Power Plan and CPU clock speed
   .DESCRIPTION
        This script can be used to validade CPU configuration and find issues at OS or BIOS settings. 
   .NOTES
        Tags: Invoke-CheckCPUConfig
        Security Requirement: Requires RPC (Remote Procedure Call) access over port 445 to collect PerfMon counters, also requires WMI(namespaces CIMV2 and Root) 
                                remote access. If remote WMI is not available, script will try to run WMI query locally via PsExec (sysinternals).
        Other Requirements: Make sure files "cpuz_x64.exe" and "PsExec64.exe" are on same folder as Invoke-CheckCPUConfig.ps1.

        How to run the script:
        
        1 - Configuring Windows PowerShell
            By default, Windows PowerShell has its ExecutionPolicy set to Restricted. This setting
            must be changed to execute the Invoke-CheckCPUConfig.ps1 PowerShell script.
            
            To apply the ExecutionPolicy to the LocalMachine, run the following command within
            the Windows PowerShell Console (be sure to start the console with "Run as administrator"):
                Set-ExecutionPolicy Unrestricted 
                Or 
                Set-ExecutionPolicy –Scope LocalMachine Unrestricted
                
                To apply the ExecutionPolicy to the current user only, run the following command within the Windows PowerShell Console:
                Set-ExecutionPolicy –Scope CurrentUser RemoteSigned
                
                Or to apply the ExecutionPolicy to the process only, run the following command within the Windows PowerShell Console:
                Set-ExecutionPolicy –Scope Process RemoteSigned
            
            Note:
            If using an ExecutionPolicy based process, it will be required to run SetExecutionPolicy each time a Windows PowerShell Console is launched.
            For more information on setting the Windows PowerShell ExecutionPolicy, please visit the following site:
            http://msdn.microsoft.com/en-us/library/bb648601(VS.85).aspx
        
        2 - Copy files "cpuz_x64.exe", "PsExec64.exe" and "Invoke-CheckCPUConfig.ps1" to a local directory (i.e. "c:\temp\").
        
        3 - Run the following command within the Windows PowerShell Console:
            PS C:\>& "C:\temp\Invoke-CheckCPUConfig.ps1" -ComputerName 'computer1', 'computer2' -ShowDebugMessages -CaptureCPUzInfo -NumberOfExecutionsCpuZ 5
        
        4 - The PS script will create the "CheckCPUConfigResult.html" output file with details about the execution.
            Some items that will be interesting to analyze and highlight to customer are:
            % Processor Performance: 
                "% Processor Performance" performance counter should as close as possible to 100.
                If this counter is less than 98, investigate further at BIOS configuration to confirm there are no 
                energy-savings functions being used.
                More information about collected counters:
                    1 - % of Maximum Frequency is the percentage of the current processor's maximum frequency.
                    2 - Actual clock speed = $MaxClockSpeed * ($ProcessorPerformance / 100)
                    3 - % Processor Performance is the average performance of the processor while it is executing instructions, 
                        as a percentage of the nominal performance of the processor.
                            You may see "% Processor Performance" running at 153% performance a.k.a. 153% of the frequency of the processor (thank you turbo boost). 
                            Processor Performance may exceed 100%... This shuold be as close to 100% as possible. 
                            Watch out for low (<95) numbers on "% Processor Performance" as this may be an indicator CPU clock speed is limited at BIOS level.

            CPUZ info - Clock Speed:
                Clock speed frequency should be equal or greater to processor "Stock frequency". Users can use the basic input and output system (BIOS) 
                setup to "optimize" the BIOS settings to meet requirements for best performance and energy efficiency. 
                Those settings usually take precedence over the Windows power plan setting. 
                If clock speed frequency is less than "stock frequency", there is a good chance this is misconfigured at BIOS level.
                    
                Energy-saving functions, whose aim is to save energy whenever possible through frequency and voltage reduction
                and through the disabling of certain function blocks and components. 
                Those options can cause performance issues with CPU-intensive applications. The higher the settings for the energy
                saving modes, the lower the performance.
                
                As reference following are some configuration options for a few of vendors:
                    HP ProLiant - Power Regulator Settings:
                        Bad options: "Dynamic Power Savings Mode" (default option), "Static Low Power Mode" and "OS Control Mode".
                        Make sure you're using "Static High Performance Mode", to make processors run at maximum power/performance at all times,
                        regardless of the OS power management policy.
                    Dell PowerEdge BIOS:
                        Bad options: "OS Control", "Active Power Controller" and Custom.
                        Make sure you're using "Static Max Performance" option. 
                            DBPM Disabled (BIOS will set P-State to MAX) 
                            Memory frequency = Maximum Performance 
                            Fan algorithm = Performance
                    Cisco: Energy or Performance Bias
                        Bad options: Balanced Performance, Balanced Power and Power Saver.
                        Make sure you're using "Maximum Performance" option.
                        Power Technology Setting:
                            For best performance, set the power technology option to Custom. 
                            If it is not set to Custom, the individual settings for Intel SpeedStep and Turbo Boost and the C6 power state are ignored.
                    
                    You may need to ask customer to contact the hardware vendor to confirm the best options are used 
                    for a CPU-intensive application environment.              
            
            PowerPlan: 
                OS Power plan should be set to High Performance. By default, Windows Server 2008 R2 sets the Balanced power plan, 
                which enables energy conservation by scaling the processor performance based on current CPU utilization.

            NumberOfLogicalProcessors vs NumberOfCores: 
                If the NumberOfLogicalProcessors is greater than NumberOfCores (physical processors), then hyper-threading is enabled. 
                Hyperthreading is usually recommended for a SQL Server environment. 
                Typically with a scalable database such as SQL Server running a database application will
                mean that the SQL Server workloads benefit Hyper-Threading.
                Therefore enable Hyper-Thread should be the default option for high-performance environments,
                unless tested and identified that the specific (some reporting/data warehouse workloads) environment 
                works best without it.

            BiosReleaseDate: 
                Many people still overlook at the importance of keep system updated with latest firmware and drivers. 
                Check hardware vendor support website to see if there are new hardware updates available.

            TurboBoost: 
                Intel Turbo Boost Technology accelerates processor peak loads, automatically allowing
                processor cores to run faster than the rated operating frequency.
                It is recommended to enabled it for SQL Server environments.

            Microcode Revision: 
                If you have time, you may want to double check whether you have the OS patch and processor microcode that 
                mitigate Spectre/Meltdown vulnerabilities installed and enabled.
                You can use https://support.microsoft.com/en-us/help/4093836/summary-of-intel-microcode-updates to confirm "microcode update revision"
                matches with value reported.

                Microsoft has a PowerShell module (https://aka.ms/SpeculationControlPS) that you can use to check the overall 
                patch status (from OS and hardware perspective). If you want a quick and easy check you can also try the
                InSpectre utility (https://www.grc.com/inspectre.htm) to check the patch status of OS and processor microcode.
                Other usefull links:
                KB4073225 - SQL Server guidance to protect against Spectre, Meltdown and Micro-architectural Data Sampling vulnerabilities
                https://support.microsoft.com/en-us/help/4073225/kb4073225-guidance-protect-sql-server-against-spectre-meltdown

                An old/unsupported OS version may not have all required updates.

            Other recommendations:
                If server is a virtualization host, make sure that VT-x and VT-d are enabled so that you can take advantage of the virtualization
                support built into your processor. Also make sure that hypervisor is using the High Performance power policy and there are
                no other CPU limitations for virtualized servers.

        Author: Fabiano Amorim, amorim@pythian.com
   .LINK
        https://github.com/mcflyamorim
        https://www.pythian.com
   .EXAMPLE
        Open a PowerShell console and run the following commands:
        PS C:\>& "C:\temp\Invoke-CheckCPUConfig.ps1" -ComputerName 'razerfabiano', 'VMWin2012_1' -ShowDebugMessages -CaptureCPUzInfo -NumberOfExecutionsCpuZ 5
   .EXAMPLE
        Open a PowerShell console and run the following commands:
        PS C:\>& "C:\temp\Invoke-CheckCPUConfig.ps1" -UseMAP_SQLServicesOut -ShowDebugMessages -CaptureCPUzInfo -NumberOfExecutionsCpuZ 3

        This will use "MAP_SQLServicesOut.csv" file to get list of computers to check
        MAP_SQLServices.ps1 can be used to generate a "MAP_SQLServicesOut.csv" file.
#>

[CmdletBinding()]
param (
         [parameter(ValueFromPipeline = $true)]
         [string[]]$ComputerName,
         [parameter()]
         [int]$NumberOfExecutionsCpuZ = 5,
         [switch]$CaptureCPUzInfo,
         [switch]$UseMAP_SQLServicesOut,
         [switch]$ShowDebugMessages
      )

function Invoke-PsExec {
    [CmdletBinding()]
    param(
        # IP address or computer name.
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)][ValidateNotNullOrEmpty()][Alias('PSComputerName', 'Cn')][string[]] $ComputerName,
        # PowerShell or batch/cmd.exe code to execute.
        [string] $Command,
        # This indicates that the specified command string is pure PowerShell code (you will usually want single quotes around that to avoid escaping).
        [switch] $IsPSCommand,
        # Use this if the PowerShell code produces a base64-encoded string of a length greater than 260, so you get 'Argument to long' [SIC] from PsExec. This uses a temporary file that's created on the remote computer.
        [switch] $IsLongPSCommand,
        # Custom parameters for PsExec.
        [string] $CustomPsExecParameters = '',
        # PowerShell file in the local file system to be run via PsExec on the remote computer.
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})][string] $PSFile = '',
        # Perform a DNS lookup.
        [switch] $Dns,
        # Pass in alternate credentials. Get-Help Get-Credential.
        [System.Management.Automation.Credential()] $Credential = [System.Management.Automation.PSCredential]::Empty,
        # Attempt PsExec command even if ping fails.
        [switch] $ContinueOnPingFail,
        # Number of concurrent threads.
        [int] $ThrottleLimit = 32,
        # Do not display progress with Write-Progress.
        [switch] $HideProgress,
        # Timeout in seconds. Causes problems if too short. 600 as a default seems OK. Increase if doing a lot of processing with PsExec.
        [int] $Timeout = 600,
        # Do not display the end summary with start and end time, using Write-Host.
        [switch] $HideSummary,
        [switch] $IsCPUzCommand,
        [string] $OtherArgs)
    
    # PowerShell Invoke-PsExec (PsExec Wrapper v2).
    # Copyright (c) 2015, Svendsen Tech, All rights reserved.
    # Author: Joakim Borger Svendsen
    # BSD 3-clause license - http://www.opensource.org/licenses/BSD-3-Clause
    # August 15, 2015. beta1
    # August 23, 2015. beta2
    # December 02, 2015, beta3, bug fixes, documentation

    begin
    {
        Set-StrictMode -Version Latest
        $MyEAP = 'Stop'
        $ErrorActionPreference = $MyEAP
        $StartTime = Get-Date
        if ($PsExecExecutable = Get-Item -LiteralPath (Join-Path ($PSScriptRoot) 'PsExec64.exe') -ErrorAction SilentlyContinue | Select-Object -ErrorAction SilentlyContinue -ExpandProperty FullName)
        {
            Write-Verbose -Message "Found PsExec64.exe in current working directory. Using this PsExec64.exe executable: '$PsExecExecutable'."
        }
        <# The .Definition turns out to be the actual code... at least when dot-sourced. Will just remove it for now.
        Write-Verbose -Message ("MyInvocation: " + ($MyInvocation.MyCommand.Name))
        elseif ($PsExecExecutable = Get-Item -LiteralPath (Join-Path (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent) 'PsExec64.exe') -ErrorAction SilentlyContinue | Select-Object -ErrorAction SilentlyContinue -ExpandProperty FullName)
        {
            Write-Verbose -Message "Found PsExec64.exe in directory script was called from. Using this PsExec64.exe executable: '$PsExecExecutable'."
        }
        #>
        elseif ($PsExecExecutable = Get-Command -Name PsExec64 -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 | Select-Object -ExpandProperty Definition -ErrorAction SilentlyContinue)
        {
            Write-Verbose -Message "Found PsExec64.exe in `$Env:PATH. Using this PsExec64.exe executable: '$PsExecExecutable'."
        }
        else
        {
            Write-Warning -Message "You need PsExec64.exe from Microsoft's SysInternals suite to use this script. Either in the working dir, or somewhere in `$Env:PATH."
            return
        }
        $RunspaceTimers = [HashTable]::Synchronized(@{})
        $Data = [HashTable]::Synchronized(@{})
        $Runspaces = New-Object -TypeName System.Collections.ArrayList
        $RunspaceCounter = 0
        Write-Verbose -Message 'Creating initial session state.'
        $ISS = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $ISS.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'RunspaceTimers', $RunspaceTimers, ''))
        $ISS.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'Data', $Data, ''))
        Write-Verbose -Message 'Creating runspace pool.'
        $RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $ISS, $Host)
        $RunspacePool.ApartmentState = 'STA'
        $RunspacePool.Open()
        # This is run for every computer.
        $PsExecScriptBlock =
        {
            [CmdletBinding()]
            param(
                [int] $ID,
                [string] $ComputerName,
                [string] $Command,
                [switch] $IsPSCommand,
                [switch] $IsLongPSCommand,
                [string] $CustomPsExecParameters,
                [string] $PSFile,
                [switch] $ContinueOnPingFail,
                [switch] $Dns,
                [string] $PsExecExecutable,
                [string] $OtherArgs,
                [switch] $IsCPUzCommand,
                $Credential
            )
            $RunspaceTimers.$ID = Get-Date
            if (-not $Data.ContainsKey($ComputerName))
            {
                $Data[$ComputerName] = New-Object -TypeName PSObject -Property @{ ComputerName = $ComputerName }
            }
            if ($Dns)
            {
                Write-Verbose -Message "${ComputerName}: Performing DNS lookup."
                $ErrorActionPreference = 'SilentlyContinue'
                $HostEntry = [System.Net.Dns]::GetHostEntry($ComputerName)
                $Result = $?
                $ErrorActionPreference = $MyEAP
                #Write-Verbose -Message "`$Result from DNS lookup: $Result (type: $($Result.GetType().FullName))"
                # It looks like it's sometimes "successful" even when it isn't, for any practical purposes (pass in IP, get the same IP as .HostName)...
                if ($Result)
                {
                    ## This is a best-effort attempt at handling things flexibly.
                    if ($HostEntry.HostName.Split('.')[0] -ieq $ComputerName.Split('.')[0])
                    {
                        $IPDns = @($HostEntry | Select -Expand AddressList | Select -Expand IPAddressToString)
                    }
                    else
                    {
                        $IPDns = @(@($HostEntry.HostName) + @($HostEntry.Aliases))
                    }
                    $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name 'IP/DNS' -Value $IPDns
                }
                else
                {
                    $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name 'IP/DNS' -Value $Null
                }
            }
            Write-Verbose -Message "${ComputerName}: Pinging."
            if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet))
            {
                $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name Ping -Value $False
                if (-not $ContinueOnPingFail)
                {
                    continue
                }
            }
            else
            {
                $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name Ping -Value $True
            }
            if ($Credential.Username -ne $Null)
            {
                [string] $CommandString = "-u `"$($Credential.Username)`" -p `"$($Credential.GetNetworkCredential().Password)`" /accepteula /nobanner $CustomPsExecParameters \\$ComputerName"
            }
            else
            {
                [string] $CommandString = "/accepteula /nobanner $CustomPsExecParameters \\$ComputerName"
            }

            if ($IsLongPSCommand -or $PSFile)
            {
                if ($IsLongPSCommand)
                {
                    $TempPSFile = [System.IO.Path]::GetTempFileName()
                    $Command | Out-File -LiteralPath $TempPSFile
                }
                elseif ($PSFile)
                {
                    $TempPSFile = $PSFile
                }
                # Try to handle multiple people running the script at the same time (race condition not handled, but it's better than nothing).
                $Destination = "\\${ComputerName}\ADMIN`$\SvendsenTechInvokePsExecTemp.ps1"
                if (Test-Path -LiteralPath $Destination)
                {
                    Write-Verbose -Message "${ComputerName}: Destination file '$Destination' already exists. Tacking on numbers until it doesn't."
                    [bool] $GotAvailableFileName = $False
                    foreach ($i in 0..10000)
                    {
                        $TempDest = $Destination -replace '\.ps1$', "$i.ps1"
                        if (-not (Test-Path -LiteralPath $TempDest))
                        {
                            $Destination = $TempDest
                            $GotAvailableFileName = $True
                            break
                        }
                    }
                    if (-not $GotAvailableFileName)
                    {
                        Write-Warning -Message "${ComputerName}: All 10,000 temp file names already present in the file system. What are you up to? Skipping this computer."
                        continue
                    }
                }
                try
                {
                    Copy-Item -LiteralPath $TempPSFile -Destination $Destination -ErrorAction Stop
                }
                catch
                {
                    Write-Warning -Message "${ComputerName}: Unable to copy (temporary) PowerShell script file to destination: '$Destination': $_"
                    if ($IsLongPSCommand)
                    {
                        Write-Verbose -Message "${ComputerName}: Deleting local temporary PS script file: '$TempPSFile'."
                        Remove-Item -LiteralPath $TempPSFile -Force -ErrorAction Continue
                    }
                    continue
                }
                if ($IsLongPSCommand)
                {
                    Write-Verbose -Message "${ComputerName}: Deleting temporary PS script file: '$TempPSFile'."
                    Remove-Item -LiteralPath $TempPSFile -Force -ErrorAction Continue
                }
                $CommandString += " cmd /c `"echo . | powershell.exe -NoLogo -ExecutionPolicy Bypass -File $Env:SystemRoot\$($Destination.Split('\')[-1])`""
            }
            elseif ($IsCPUzCommand)
            {
                $CommandString += " -c `"$Command`" " + $OtherArgs
                Write-Verbose -Message "${ComputerName}: CommandString = $CommandString"
            }
            elseif ($IsPSCommand)
            {
                #$EncodedCommand = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))
                $CommandString += " cmd /c `"echo . | powershell.exe -NoLogo -ExecutionPolicy Bypass -Command $Command`""
                Write-Verbose -Message "${ComputerName}: CommandString = $CommandString"
            }
            else
            {
                $CommandString += " cmd /c `"$Command`""
                Write-Verbose -Message "${ComputerName}: CommandString = $CommandString"
            }
            $TempFileNameSTDOUT = [System.IO.Path]::GetTempFileName()
            $TempFileNameSTDERR = [System.IO.Path]::GetTempFileName()
            Write-Verbose -Message "${ComputerName}: Running PsExec command."
            $Result = Start-Process -FilePath $PsExecExecutable -ArgumentList $CommandString -Wait -NoNewWindow -PassThru -RedirectStandardOutput $TempFileNameSTDOUT -RedirectStandardError $TempFileNameSTDERR -ErrorAction Continue
            $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name ExitCode -Value $Result.ExitCode
            $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name STDOUT -Value ((Get-Content -LiteralPath $TempFileNameSTDOUT) -join "`n")
            #Write-Verbose -Message ('Content of temp STDERR file: ' + ((Get-Content -LiteralPath $TempFileNameSTDERR) -join "`n"))
            $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name STDERR -Value ((Get-Content -LiteralPath $TempFileNameSTDERR) -join "`n")
            Write-Verbose -Message "${ComputerName}: Deleting local STDOUT temporary file: '$TempFileNameSTDOUT'."
            Remove-Item -LiteralPath $TempFileNameSTDOUT -Force -ErrorAction Continue
            Write-Verbose -Message "${ComputerName}: Deleting local STDERR temporary file: '$TempFileNameSTDERR'."
            Remove-Item -LiteralPath $TempFileNameSTDERR -Force -ErrorAction Continue
            if ($IsLongPSCommand -or $PSFile)
            {
                Write-Verbose -Message "${ComputerName}: Deleting remote temporary PowerShell file: '$Destination'."
                Remove-Item -LiteralPath $Destination -ErrorAction Continue
            }
        }

        function Get-Result
        {
            [CmdletBinding()]
            param(
                [switch] $Wait
            )
            do
            {
                $More = $false
                foreach ($Runspace in $Runspaces) {
                    $StartTime = $RunspaceTimers[$Runspace.ID]
                    if ($Runspace.Handle.IsCompleted)
                    {
                        #Write-Verbose -Message ('Thread done for {0}' -f $Runspace.IObject)
                        $Runspace.PowerShell.EndInvoke($Runspace.Handle)
                        $Runspace.PowerShell.Dispose()
                        $Runspace.PowerShell = $null
                        $Runspace.Handle = $null
                    }
                    elseif ($Runspace.Handle -ne $null)
                    {
                        $More = $true
                    }
                    if ($Timeout -and $StartTime)
                    {
                        if ((New-TimeSpan -Start $StartTime).TotalSeconds -ge $Timeout -and $Runspace.PowerShell) {
                            Write-Warning -Message ('Timeout {0}' -f $Runspace.IObject)
                            $Runspace.PowerShell.Dispose()
                            $Runspace.PowerShell = $null
                            $Runspace.Handle = $null
                        }
                    }
                }
                if ($More -and $PSBoundParameters['Wait'])
                {
                    Start-Sleep -Milliseconds 100
                }
                foreach ($Thread in $Runspaces.Clone())
                {
                    if (-not $Thread.Handle) {
                        Write-Verbose -Message ('Removing {0} from runspaces' -f $Thread.IObject)
                        $Runspaces.Remove($Thread)
                    }
                }
                if (-not $HideProgress)
                {
                    $ProgressSplatting = @{
                        Activity = 'Running PsExec Commands'
                        Status = 'Processing: {0} of {1} total threads done' -f ($RunspaceCounter - $Runspaces.Count), $RunspaceCounter
                        PercentComplete = ($RunspaceCounter - $Runspaces.Count) / $RunspaceCounter * 100
                    }
                    Write-Progress @ProgressSplatting
                }
            }
            while ($More -and $PSBoundParameters['Wait'])
        } # end of Get-Result
    }

    process
    {
        foreach ($Computer in $ComputerName)
        {
            Write-Verbose -Message "Processing $Computer."
            ++$RunspaceCounter
            $psCMD = [System.Management.Automation.PowerShell]::Create().AddScript($PsExecScriptBlock)
            [void] $psCMD.AddParameter('ID', $RunspaceCounter)
            [void] $psCMD.AddParameter('ComputerName', $Computer)
            [void] $PSCMD.AddParameter('Command', $Command)
            [void] $PSCMD.AddParameter('IsPSCommand', $IsPSCommand)
            [void] $PSCMD.AddParameter('CustomPsExecParameters', $CustomPsExecParameters)
            [void] $PSCMD.AddParameter('PSFile', $PSFile)
            [void] $PSCMD.AddParameter('IsLongPSCommand', $IsLongPSCommand)
            [void] $PSCMD.AddParameter('Dns', $Dns)
            [void] $PSCMD.AddParameter('PsExecExecutable', $PsExecExecutable)
            [void] $PSCMD.AddParameter('ContinueOnPingFail', $ContinueOnPingFail)
            [void] $PSCMD.AddParameter('OtherArgs', $OtherArgs)
            [void] $PSCMD.AddParameter('IsCPUzCommand', $IsCPUzCommand)
            [void] $PSCMD.AddParameter('Credential', $Credential)
            [void] $psCMD.AddParameter('Verbose', $VerbosePreference)
            $psCMD.RunspacePool = $RunspacePool
            [void]$Runspaces.Add(@{
                Handle = $psCMD.BeginInvoke()
                PowerShell = $psCMD
                IObject = $Computer
                ID = $RunspaceCounter
            })
            Get-Result
        }
    }
    
    end 
    {
        Get-Result -Wait
        if (-not $HideProgress)
        {
            Write-Progress -Activity 'Running PsExec Commands' -Status 'Done' -Completed
        }
        Write-Verbose -Message "Closing and disposing runspace pool."
        $RunspacePool.Close()
        $RunspacePool.Dispose()
        [hashtable[]] $PsExecProperties = @{ Name = 'ComputerName'; Expression = { $_.Name } }
        if ($Dns)
        {
            $PsExecProperties += @{ Name = 'IP/DNS'; Expression = { $_.Value.'IP/DNS' } }
        }
        $PsExecProperties += @{ Name = 'Ping'; Expression = { $_.Value.Ping } },
                             @{ Name = 'ExitCode'; Expression = { $_.Value.ExitCode } },
                             @{ Name = 'STDOUT'; Expression = { $_.Value.STDOUT } },
                             @{ Name = 'STDERR'; Expression = { $_.Value.STDERR } }
        $Data.GetEnumerator() | Select-Object -Property $PsExecProperties
        Write-Verbose -Message '"Exporting" $Global:STPsExecData and $Global:STPsExecDataProperties'
        $Global:STPsExecData = $Data
        $Global:STPsExecDataProperties = $PsExecProperties
        if (-not $HideSummary)
        {
            Write-Host -ForegroundColor Green ('Start time: ' + $StartTime)
            Write-Host -ForegroundColor Green ('End time:   ' + (Get-Date))
        }
    }
}

Clear-Host

# If running on my Lab... change variables...
if ([System.Net.Dns]::GetHostName() -eq 'dellfabiano'){
    $ComputerName = 'dellfabiano' , 'VM1'
    $ShowDebugMessages = $true
    $CaptureCPUzInfo = $true
    $NumberOfExecutionsCpuZ = 5
}

# Checking parameters
if (($ComputerName -ne $nul) -and ($UseMAP_SQLServicesOut)){
    $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
    Write-Warning "[$dt] Parameters ComputerName and UseMAP_SQLServicesOut are not compatible, use one or another."
    Return
}
if (($NumberOfExecutionsCpuZ -gt 10) -or ($NumberOfExecutionsCpuZ -lt 1) ){
    $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
    Write-Warning "[$dt] Parameter NumberOfExecutionsCpuZ invalid... Please use a number between 1 and 10."
    Return
}
if ($UseMAP_SQLServicesOut){
    if (Test-Path -Path "$PSScriptRoot/MAP_SQLServicesOut.csv" -PathType Leaf){
        # Use MAP_SQLServicesOut.csv file as source to computer list
        if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Reading MAP_SQLServicesOut.csv content from Path '$PSScriptRoot\MAP_SQLServicesOut.csv'" -ForegroundColor Yellow}
        try {
            $p = Import-Csv -Path $PSScriptRoot\MAP_SQLServicesOut.csv
            $ComputerName = $p.ComputerName | Get-Unique
            $All = $ComputerName.Count
            if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Found $All computers on MAP_SQLServicesOut.csv file..." -ForegroundColor Yellow}
        }
        catch {
            $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; 
            Write-Warning "[$dt] Failed to read MAP_SQLServicesOut.csv file. $($_)"
            Return
        }
    }
    else {
        $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; 
        Write-Warning "[$dt] Could not find file $PSScriptRoot/MAP_SQLServicesOut.csv, please make sure you've copied the file to same folder of Invoke-CheckCPUConfig.ps1"
        Return
    }
}

# Check if PS is running on evelated console
if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Checking if PS is running on evelated console" -ForegroundColor Yellow}
$User = [Security.Principal.WindowsIdentity]::GetCurrent()
$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if(!$Role) {
    $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; 
    Write-Warning "[$dt] Ops, to run this script you will need an elevated Windows PowerShell console..."	
    Return
}

# # Installing dbatools module...
# if (Test-Path -Path "$PSScriptRoot\dbatools\dbatools.psd1" -PathType Leaf){
#     try {
#         if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Importing dbatools Powershell module" -ForegroundColor Yellow}
#         Get-ChildItem -Path "$PSScriptRoot\dbatools\" -Recurse | Unblock-File
#         Import-Module "$PSScriptRoot\dbatools\dbatools.psd1" -Scope Local
#         if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Installed dbatools" -ForegroundColor Yellow}
#     }
#     catch {
#         $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; 
#         Write-Error "[$dt] Failed to Install dbatools $($_)"
#         Return
#     }
# }
# else {
#     $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; 
#     Write-Warning "[$dt] Could not find file $PSScriptRoot\dbatools\dbatools.psd1, please make sure you've copied dbatools folder to same folder of Invoke-CheckCPUConfig.ps1"
#     Return
# }

# Function to help me parse psexec result 
function ParseStr ([string]$STDOut, [string]$ColName) {
    [string]$Return = ''
    [array]$tmpArray = $STDOut.Split([Environment]::NewLine)
    foreach ($row in $tmpArray){
        $row2 = ($row.Split('=')).Trim()
        if ($row2[0] -ne $nul){
            if ($row2[0].Contains($ColName)){
                [String]$Return = $row2[1]
                break
            }
        }
    }
    $Return
}

$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; 
Write-Host "[$dt] Working on CPU usage check"

$All = $ComputerName.Count
[array] $GetResult = @()
$GetResultHTMLFragment = ''
$ComputerNum = 0

# Initializing html file...
$All | Out-File "$PSScriptRoot\CheckCPUConfigResult.html" -Force

foreach ($Computer in $ComputerName){
    $ComputerNum++
    $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; 
    $ComputerPerfmon = $Computer
    # if it is running it local... change it o localhost to avoid issues with PsExec
    if ($Computer -eq [System.Net.Dns]::GetHostName()) {
        $Computer = 'localhost'
        $ComputerPerfmon = [System.Net.Dns]::GetHostName()
    }
    
    Write-Host "[$dt] Working on $Computer [$ComputerNum out of $All]..."
    try {
        if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Trying to read PerfMon counter \\$ComputerPerfmon\Processor(_Total)\% Processor Time" -ForegroundColor Yellow}
        $ProcessorTime = (Get-Counter -Counter "\\$ComputerPerfmon\Processor(_Total)\% Processor Time" -ErrorAction Stop).CounterSamples.CookedValue
        if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] All good with remote PerfMon access, % Processor Time = $ProcessorTime" -ForegroundColor Yellow}

        if ($CaptureCPUzInfo){
            $OutCPUzInfo = @()
            # Run cpuz $NumberOfExecutionsCpuZ times and capture report result
            for ($i=1; $i -le $NumberOfExecutionsCpuZ; $i++){
                if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] CaptureCPUzInfo is enabled, running CPUz via PsExec ($i of $NumberOfExecutionsCpuZ)..." -ForegroundColor Yellow}
                [array] $tmp = @()
                
                $tmp = Invoke-PsExec -ComputerName $Computer -Command "$PSScriptRoot\cpuz_x64.exe" -OtherArgs "-txt=CpuzReport$i" -IsCPUzCommand -HideSummary -HideProgress -CustomPsExecParameters '-n 300'             
                # Checking if PsExec ran successfully
                if ($tmp -ne $nul){
                    [int]$PsExecReturnCode = $tmp | Select-Object -ExpandProperty ExitCode -ErrorAction SilentlyContinue
                    [string]$tmpSTDErr = $tmp | Select-Object -ExpandProperty STDErr
                    if ($PsExecReturnCode -ne 0) {
                        Throw $tmpSTDErr
                    }
                }
                if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] CPUz ran successfully ($i of $NumberOfExecutionsCpuZ)..." -ForegroundColor Yellow}
                if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Running TYPE %systemroot%\CpuzReport$i.txt via PsExec to read CPUz result ($i of $NumberOfExecutionsCpuZ)..." -ForegroundColor Yellow}
                $tmp = Invoke-PsExec -ComputerName $Computer -Command "TYPE %systemroot%\CpuzReport$i.txt" -HideSummary -HideProgress -CustomPsExecParameters '-n 300'

                [int]$PsExecReturnCode = $tmp | Select-Object -ExpandProperty ExitCode -ErrorAction SilentlyContinue
                [string]$tmpSTDErr = $tmp | Select-Object -ExpandProperty STDErr
                if ($PsExecReturnCode -ne 0) {
                    Throw $tmpSTDErr
                }
                [string]$tmpSTDOut = $tmp | Select-Object -ExpandProperty STDOut
                if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] TYPE %systemroot% ran successfully ($i of $NumberOfExecutionsCpuZ)..." -ForegroundColor Yellow}
                if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Starting to parse CPUz result... ($i of $NumberOfExecutionsCpuZ)..." -ForegroundColor Yellow}
                if ($tmp -ne $nul){
                    # Parsing cpuz result to grab only "Processors Information" data
                    if (($tmpSTDOut.IndexOf("Processors Information") -gt -1) -and ($tmpSTDOut.IndexOf("Thread dumps") -gt -1)){
                        $tmpSTDOut = $tmpSTDOut.SubString($tmpSTDOut.IndexOf("Processors Information"), $tmpSTDOut.LastIndexOf("Thread dumps") - $tmpSTDOut.IndexOf("Processors Information") - 1)
                    }
                    [float]$StockFrequency = 0
                    [float]$ClockSpeedtmp = 0
                    $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss.fff'
                    $OutCPUzInfo += [pscustomobject] @{
                        Execution = "$i of $NumberOfExecutionsCpuZ"
                        Property =  "Captured DateTime"
                        Val = $dt
                    }
                    foreach ($row in $tmpSTDOut -split "`n"){
                        $row = $row.trim()
                        $row = $row -Replace '\s\s+', ": "
                        $row = $row.Replace("`t", ": ")
                        if ($row -like "Socket*"){
                            $SocketID = $row.SubString($row.IndexOf("ID = "), $row.Length - $row.IndexOf("ID = "))
                            $OutCPUzInfo += [pscustomobject] @{
                                Execution = "$i of $NumberOfExecutionsCpuZ"
                                Property =  "Socket ($SocketID)"
                                Val = $row.SubString($row.IndexOf(":") + 2, $row.Length - ($row.IndexOf(":") + 2))}
                        }
                        if ($row -like "Number of cores*"){
                            $OutCPUzInfo += [pscustomobject] @{
                                Execution = "$i of $NumberOfExecutionsCpuZ"
                                Property =  "Number of cores ($SocketID)"
                                Val = $row.SubString($row.IndexOf(":") + 2, $row.Length - ($row.IndexOf(":") + 2))}
                        }
                        if ($row -like "Turbo Mode*"){
                            $OutCPUzInfo += [pscustomobject] @{
                                Execution = "$i of $NumberOfExecutionsCpuZ"
                                Property =  "Turbo Mode ($SocketID)"
                                Val = $row.SubString($row.IndexOf(":") + 2, $row.Length - ($row.IndexOf(":") + 2))}
                        }
                        if ($row -like "Multiplier x Bus Speed*"){
                            $OutCPUzInfo += [pscustomobject] @{
                                Execution = "$i of $NumberOfExecutionsCpuZ"
                                Property =  "Multiplier x Bus Speed ($SocketID)"
                                Val = $row.SubString($row.IndexOf(":") + 2, $row.Length - ($row.IndexOf(":") + 2))}
                        }
                        if ($row -like "Rated Bus speed*"){
                            $OutCPUzInfo += [pscustomobject] @{
                                Execution = "$i of $NumberOfExecutionsCpuZ"
                                Property =  "Rated Bus speed ($SocketID)"
                                Val = $row.SubString($row.IndexOf(":") + 2, $row.Length - ($row.IndexOf(":") + 2))}
                        }
                        if ($row -like "Microcode Revision*"){
                            $OutCPUzInfo += [pscustomobject] @{
                                Execution = "$i of $NumberOfExecutionsCpuZ"
                                Property =  "Microcode Revision ($SocketID)"
                                Val = $row.SubString($row.IndexOf(":") + 2, $row.Length - ($row.IndexOf(":") + 2))}
                        }
                        if (($row -like "Ratio*") -and ($row -notlike "*n.a.*")){
                            $OutCPUzInfo += [pscustomobject] @{
                                Execution = "$i of $NumberOfExecutionsCpuZ"
                                Property =  $row.SubString(0, $row.IndexOf(": ")) +  "($SocketID)"
                                Val = $row.SubString($row.IndexOf(":") + 2, $row.Length - ($row.IndexOf(":") + 2))}
                        }
                        if ($row -like "Stock frequency*") {
                            $OutCPUzInfo += [pscustomobject] @{
                                Execution = "$i of $NumberOfExecutionsCpuZ"
                                Property =  "Stock frequency ($SocketID)"
                                Val = $row.SubString($row.IndexOf(":") + 2, $row.Length - ($row.IndexOf(":") + 2))}
                            [float]$StockFrequency = ($row.Replace("Stock frequency: ", "")) -Replace " MHz", ""
                        }
                        if (($row -like "Clock Speed*") -and ($row -notlike "*n.a.*")){
                            if ($row.IndexOf(" MHz") -ne -1){
                                [float]$ClockSpeedtmp = $row.SubString($row.IndexOf(": ") + 1, $row.IndexOf(" MHz") - $row.IndexOf(":") -1)
                                [string]$row3 = ''
                                if ($ClockSpeedtmp -le $StockFrequency){
                                    $row3 = 'Red*****' + $row.SubString($row.IndexOf(":") + 2, $row.Length - ($row.IndexOf(":") + 2)) + 'Red#####'
                                }
                                else{
                                    $row3 = 'Green*****' + $row.SubString($row.IndexOf(":") + 2, $row.Length - ($row.IndexOf(":") + 2)) + 'Green#####'
                                }
                                $OutCPUzInfo += [pscustomobject] @{
                                    Execution = "$i of $NumberOfExecutionsCpuZ"
                                    Property =  $row.SubString(0, $row.IndexOf(": ")) + "($SocketID)"
                                    Val = $row3}
                            }
                        }
                        if ($row -like "Core Speed*") {
                            $OutCPUzInfo += [pscustomobject] @{
                                Execution = "$i of $NumberOfExecutionsCpuZ"
                                Property =  "Core Speed ($SocketID)"
                                Val = $row.SubString($row.IndexOf(":") + 2, $row.Length - ($row.IndexOf(":") + 2))}
                        }
                    }
                }
                else {
                    $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; 
                    Write-Warning "[$dt] Couln't run CPUz via PsExec... Check prior messages for more information..."
                }
                Start-Sleep -Seconds 1
            }
        }

        # Converting Rows into Columns...
        $b = @()
        foreach ($Property in $OutCPUzInfo.Property | Select-Object -Unique) {
            $Props = [ordered]@{ Property =  $Property }
            foreach ($Execution in $OutCPUzInfo.Execution | Select-Object -Unique){ 
                $Val = ($OutCPUzInfo.where({ $_.Execution -eq $Execution -and 
                            $_.Property -eq $Property })).Val
                $Props += @{ $Execution = $Val }
            }
            $b += New-Object -TypeName PSObject -Property $Props
        }
        $OutCPUzInfoHtmlFragment = $b

        if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Trying to get OS details via Win32_OperatingSystem WMI class... Running Get-CimInstance..." -ForegroundColor Yellow}
        #$Win32_OperatingSystem = Get-DbaCmObject -ComputerName $Computer -ClassName Win32_OperatingSystem | Select-Object Caption, Version
        $Win32_OperatingSystem = Get-CimInstance -ComputerName $Computer -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object Caption, Version

        # if $Win32_OperatingSystem is null it probably means WMI/CIM call failed...
        # trying to run WMI commands via PsExec(SysInternals)
        if ($Win32_OperatingSystem -eq $nul){
            if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Remote WMI access is not working :-( ..." -ForegroundColor Yellow}
            if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Trying to run WMIC command via PsExec(SysInternals), this may take some time to run. Be patient, it is not my fault." -ForegroundColor Yellow}
            
            [array] $tmp = @()
            $tmp = Invoke-PsExec -ComputerName $Computer -Command "WMIC OS Get Caption, Version /FORMAT:List" -HideSummary -HideProgress -CustomPsExecParameters '-n 300'
            # Checking if PsExec ran successfully
            [int]$PsExecReturnCode = $tmp | Select-Object -ExpandProperty ExitCode -ErrorAction SilentlyContinue
            [string]$tmpSTDErr = $tmp | Select-Object -ExpandProperty STDErr
            if ($PsExecReturnCode -ne 0) {
                Throw $tmpSTDErr
            }
            [string]$tmpSTDOut = $tmp | Select-Object -ExpandProperty STDOut
            $WinCaption = ParseStr -STDOut $tmpSTDOut -ColName 'Caption'
            $WinVersion = ParseStr -STDOut $tmpSTDOut -ColName 'Version'
            if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Nice, old but gold PsExec worked fine... Win32_OperatingSystem.Caption = $WinCaption; Win32_OperatingSystem.Version = $WinVersion" -ForegroundColor Yellow}
        }
        else{
            $WinVersion = $Win32_OperatingSystem.Version
            $WinCaption = $Win32_OperatingSystem.Caption
            if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] All good with remote WMI access. Win32_OperatingSystem.Caption = $WinCaption; Win32_OperatingSystem.Version = $WinVersion" -ForegroundColor Yellow}
        }

        # Operating system	      | Version number
        # Windows Server 2019	  | 10.0*
        # Windows Server 2016	  | 10.0*
        # Windows Server 2012 R2  | 6.3*
        # Windows Server 2012	  | 6.2
        # Windows Server 2008 R2  | 6.1
        # Windows Server 2008	  | 6.0
        # Windows Server 2003 R2  | 5.2
        if (($WinVersion -like '6.2*') -or ($WinVersion -like '6.3*') -or ($WinVersion -like '10.*') -or ($WinVersion -eq $nul)){
            if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Reading PerfCounter % Processor Performance" -ForegroundColor Yellow}
            $ProcessorPerformance = (Get-Counter -Counter "\\$ComputerPerfmon\Processor Information(_Total)\% Processor Performance" -ErrorAction SilentlyContinue).CounterSamples.CookedValue
            if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Reading PerfCounter % of Maximum Frequency" -ForegroundColor Yellow}
            $MaximumFrequency = (Get-Counter -Counter "\\$ComputerPerfmon\Processor Information(_Total)\% of Maximum Frequency" -ErrorAction SilentlyContinue).CounterSamples.CookedValue
            if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Reading PerfCounter % Performance Limit" -ForegroundColor Yellow}
            $PerformanceLimit = (Get-Counter -Counter "\\$ComputerPerfmon\Processor Information(_Total)\% Performance Limit" -ErrorAction SilentlyContinue).CounterSamples.CookedValue
        }
        else{
            $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; 
            Write-Warning "[$dt] Windows < 2012, limited information captured. WinVersion = $WinVersion"
            $ProcessorPerformance = 0
            $MaximumFrequency = 0
            $PerformanceLimit = 0
        }

        # if $Win32_OperatingSystem is null it probably means WMI/CIM call failed...
        # trying to run WMI commands via PsExec(SysInternals)
        if ($Win32_OperatingSystem -eq $nul){
            [array] $tmp = @()
            $tmp = Invoke-PsExec -ComputerName $Computer -Command "WMIC COMPUTERSYSTEM Get Manufacturer, Model, NumberOfLogicalProcessors, NumberOfProcessors /FORMAT:List" -HideSummary -HideProgress -CustomPsExecParameters '-n 300'
            # Checking if PsExec ran successfully
            [int]$PsExecReturnCode = $tmp | Select-Object -ExpandProperty ExitCode -ErrorAction SilentlyContinue
            [string]$tmpSTDErr = $tmp | Select-Object -ExpandProperty STDErr
            if ($PsExecReturnCode -ne 0) {
                Throw $tmpSTDErr
            }
            [string]$tmpSTDOut = $tmp | Select-Object -ExpandProperty STDOut
            $Manufacturer = ParseStr -STDOut $tmpSTDOut -ColName 'Manufacturer'
            $Model = ParseStr -STDOut $tmpSTDOut -ColName 'Model'
            $NumberOfLogicalProcessors = ParseStr -STDOut $tmpSTDOut -ColName 'NumberOfLogicalProcessors'
            $NumberOfProcessors = ParseStr -STDOut $tmpSTDOut -ColName 'NumberOfProcessors'

            [array] $tmp = @()
            $tmp = Invoke-PsExec -ComputerName $Computer -Command "WMIC BIOS Get BIOSVersion, ReleaseDate /FORMAT:List" -HideSummary -HideProgress -CustomPsExecParameters '-n 300'
            # Checking if PsExec ran successfully
            [int]$PsExecReturnCode = $tmp | Select-Object -ExpandProperty ExitCode -ErrorAction SilentlyContinue
            [string]$tmpSTDErr = $tmp | Select-Object -ExpandProperty STDErr
            if ($PsExecReturnCode -ne 0) {
                Throw $tmpSTDErr
            }
            [string]$tmpSTDOut = $tmp | Select-Object -ExpandProperty STDOut
            $BIOSVersion = ParseStr -STDOut $tmpSTDOut -ColName 'BIOSVersion'
            $ReleaseDate = ParseStr -STDOut $tmpSTDOut -ColName 'ReleaseDate'
            $ReleaseDate = $ReleaseDate.SubString(0, 8)
            $ReleaseDate = [datetime]::parseexact($ReleaseDate, 'yyyyMMdd', $null)

            [array] $tmp = @()
            $tmp = Invoke-PsExec -ComputerName $Computer -Command "WMIC CPU WHERE 'DeviceID='CPU0'' GET Name, MaxClockSpeed, NumberOfCores /FORMAT:List" -HideSummary -HideProgress -CustomPsExecParameters '-n 300'
            # Checking if PsExec ran successfully
            [int]$PsExecReturnCode = $tmp | Select-Object -ExpandProperty ExitCode -ErrorAction SilentlyContinue
            [string]$tmpSTDErr = $tmp | Select-Object -ExpandProperty STDErr
            if ($PsExecReturnCode -ne 0) {
                Throw $tmpSTDErr
            }
            [string]$tmpSTDOut = $tmp | Select-Object -ExpandProperty STDOut
            $MaxClockSpeed = ParseStr -STDOut $tmpSTDOut -ColName 'MaxClockSpeed'
            $NumberOfCores = ParseStr -STDOut $tmpSTDOut -ColName 'NumberOfCores'
            $ProcessorDescription = ParseStr -STDOut $tmpSTDOut -ColName 'Name'
        }
        else {
            $Win32_ComputerSystem = Get-CimInstance -ComputerName $Computer -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model, NumberOfLogicalProcessors, NumberOfProcessors
            $Manufacturer = $Win32_ComputerSystem.Manufacturer
            $Model = $Win32_ComputerSystem.Model
            $NumberOfLogicalProcessors = $Win32_ComputerSystem.NumberOfLogicalProcessors
            $NumberOfProcessors = $Win32_ComputerSystem.NumberOfProcessors

            $Win32_BIOS = Get-CimInstance -ComputerName $Computer -ClassName Win32_BIOS | Select-Object BIOSVersion, ReleaseDate
            $BIOSVersion = $Win32_BIOS.BIOSVersion
            $ReleaseDate = $Win32_BIOS.ReleaseDate

            $ProcessorInfo = Get-CimInstance -ComputerName $Computer -ClassName CIM_Processor | Where-Object {$_.DeviceId -eq 'CPU0'}
            $MaxClockSpeed = $ProcessorInfo.MaxClockSpeed
            $NumberOfCores = $ProcessorInfo.NumberOfCores
            $ProcessorDescription = $ProcessorInfo.Name
        }

        $ProcessorTime = [math]::Round($ProcessorTime,2)
        $ProcessorPerformance = [math]::Round($ProcessorPerformance,2)
        $MaximumFrequency = [math]::Round($MaximumFrequency,2)
        $PerformanceLimit = [math]::Round($PerformanceLimit,2)

        # Calculating CurrentClockSpeed
        $CurrentClockSpeed = $MaxClockSpeed*($ProcessorPerformance/100)
        $CurrentClockSpeed = [math]::Round($CurrentClockSpeed,2)

        if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Trying to capture PowerPlan setting via WMI accessing class win32_PowerPlan" -ForegroundColor Yellow}
        #$PowerPlan = Get-DbaPowerPlan -ComputerName $Computer | Select-Object -ExpandProperty PowerPlan

        $PowerPlan = $null
        try
        {
            $PowerPlan = Get-WmiObject -ComputerName $Computer -NS 'root\cimv2\power' -Class 'win32_PowerPlan' -Filter "isActive=true" | Select-Object -ExpandProperty ElementName
        }
        catch
        {
            $PowerPlan = $null
        }

        if (-not $PowerPlan){
            if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] It was not possible to capture PowerPlan setting via Get-DbaPowerPlan... Calling PsExec for rescure..." -ForegroundColor Yellow}
            [array] $tmp = @()
            $tmp = Invoke-PsExec -ComputerName $Computer -Command "WMIC /namespace:\\root\cimv2\power path Win32_PowerPlan WHERE 'IsActive='TRUE'' GET ElementName /FORMAT:List" -HideSummary -HideProgress -CustomPsExecParameters '-n 300'
            # Checking if PsExec ran successfully
            if ($tmp -ne $nul){
                [int]$PsExecReturnCode = $tmp | Select-Object -ExpandProperty ExitCode -ErrorAction SilentlyContinue
                [string]$tmpSTDErr = $tmp | Select-Object -ExpandProperty STDErr
                if ($PsExecReturnCode -ne 0) {
                    Throw $tmpSTDErr
                }
                [string]$tmpSTDOut = $tmp | Select-Object -ExpandProperty STDOut
                $PowerPlan = ParseStr -STDOut $tmpSTDOut -ColName 'ElementName'
            }
            else {
                $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; 
                Write-Warning "[$dt] Couln't get Power Plan via PsExec... Check prior messages for more information..."
            }
        }
        else {
            if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Get-DbaPowerPlan worked fine... PowerPlan = $PowerPlan" -ForegroundColor Yellow}
        }

        $BIOSAge = ((Get-Date) - $ReleaseDate).Days
        $BIOSUpdateDate = (Get-Date ($ReleaseDate) -Format d) + $(" ($BIOSAge", "days ago)")

        [array] $GetResultLocal = @()
        $GetResultLocal = $PowerPlan | Select-Object @{Name="ComputerName";Expression={ $Computer }}, `
                                                        @{Name="OS Caption";Expression={ $WinCaption }}, `
                                                        @{Name="OS Version";Expression={ $WinVersion }}, `
                                                        @{Name="Manufacturer";Expression={ $Manufacturer }}, `
                                                        @{Name="Model";Expression={ $Model }}, `
                                                        @{Name="BIOSVersion";Expression={ $BIOSVersion }}, `
                                                        @{Name="BIOSReleaseDate";Expression={ $BIOSUpdateDate }}, `
                                                        @{Name="Processor Description";Expression={ $ProcessorDescription }}, `
                                                        @{Name="NumberOfLogicalProcessors";Expression={ $NumberOfLogicalProcessors }}, `
                                                        @{Name="NumberOfCores";Expression={ $NumberOfCores }}, `
                                                        @{Name="NumberOfProcessors";Expression={ $NumberOfProcessors }}, `
                                                        @{Name="PowerPlan";Expression={ $PowerPlan }}, `
                                                        @{Name="Max Clock Speed";Expression={ $MaxClockSpeed }}, `
                                                        @{Name="Current Processor Speed";Expression={ $CurrentClockSpeed }}, `
                                                        @{Name="% Processor Time";Expression={ $ProcessorTime }}, `
                                                        @{Name="% Processor Performance";Expression={ $ProcessorPerformance }}, `
                                                        @{Name="% of Maximum Frequency";Expression={ $MaximumFrequency }}, `
                                                        @{Name="% Performance Limit";Expression={ $PerformanceLimit }}, `
                                                        @{Name="CPUZ info";Expression={ $OutCPUzInfoHtmlFragment | ConvertTo-Html -Property * -Fragment -As Table }}

        $GetResultLocal | Format-List
        $GetResultHTMLFragment += $GetResultLocal | ConvertTo-Html -Property * -Fragment -As List -PreContent "<h2>Computer $Computer</h2>"
        $GetResultHTMLFragment = $GetResultHTMLFragment -replace '&lt;', '<'
        $GetResultHTMLFragment = $GetResultHTMLFragment -replace '&gt;', '>'

        $GetResult += $GetResultLocal

        $header = @"
<style>
    h1 {

        font-family: Arial, Helvetica, sans-serif;
        color: #395870;
        font-size: 24px;

    }
    h2 {

        font-family: Arial, Helvetica, sans-serif;
        color: #293f50;
        font-size: 16px;

    }
    table {
		font-size: 12px;
		border: solid #395870;
		border-width: 1px;
		font-family: Arial, Helvetica, sans-serif;
	} 
    td {
		padding: 4px;
		margin: 0px;
		border: 0;
	}
    th {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 12px;
        padding: 7px 15px;
        vertical-align: middle;
	}
    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }
    .HighPerformance {
        color: #008000;
    }
    .Balanced {
        color: #ff0000;
    }
    .PowerSaver {
        color: #ff0000;
    }
</style>
"@

        # If "% Processor Performance" is lower than 95... Change text on html to Red...
        foreach ($row in $GetResult){
            [int]$row2 = $row.'% Processor Performance'
            if ($row2 -le 95){
                $row.'% Processor Performance' = '***' + $row.'% Processor Performance'
            }
        }

        $HTMLResult = $GetResult | Select-Object 'ComputerName', 'OS Caption', 'Manufacturer', 'Processor Description', 'BIOSReleaseDate', 'PowerPlan', 'Max Clock Speed', 'Current Processor Speed', '% Processor Time', '% Processor Performance' `
                            | ConvertTo-Html -PreContent "<h1>CPU configuration check report</h1>" -Property * -Fragment

        $HTMLResult = $HTMLResult.Replace("<td>***", '<td style="color:#ff0000">')
        $HTMLResult = ConvertTo-Html -Head $header -Body "$HTMLResult <h1>Detailed report</h1> $GetResultHTMLFragment" `
                                        -Title "CPU configuration check report" -PostContent "<p>Creation Date: $(Get-Date)</p>"

        $HTMLResult = $HTMLResult.Replace("Red#####", '</font>')
        $HTMLResult = $HTMLResult.Replace("Red*****", '<font color="#ff0000">')

        $HTMLResult = $HTMLResult.Replace("Green#####", '</font>')
        $HTMLResult = $HTMLResult.Replace("Green*****", '<font color="#008000">')

        $HTMLResult = $HTMLResult.Replace("---------- Execution number", '<strong>---------- Execution number')
        $HTMLResult = $HTMLResult.Replace(" ----------", ' ----------</strong>')

        $HTMLResult = $HTMLResult -replace '<td>Balanced</td>','<td class="Balanced">Balanced</td>' 
        $HTMLResult = $HTMLResult -replace '<td>Power saver</td>','<td class="PowerSaver">Power saver</td>'
        $HTMLResult = $HTMLResult -replace '<td>High performance</td>','<td class="HighPerformance">High performance</td>'

        # Saving result into a .html file
        if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Saving results to $PSScriptRoot\CheckCPUConfigResult.html" -ForegroundColor Yellow}
        $HTMLResult | Out-File "$PSScriptRoot\CheckCPUConfigResult.html" -Force

    } catch {
        $dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; 
        Write-Warning "[$dt] Error trying collect data for $Computer. Maybe a credential issue? Please confirm the computer is accessible and try again."
        Write-Warning ("[$dt] {0}" -f $_.Exception.Message)
        Write-Warning "[$dt] Value of variable tmp is: $tmp"
        
        continue
    }
}

Write-Host "-------------------------------------------------------------------- `r" 

# Showing result to PS console output 
if ($ShowDebugMessages){$dt = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'; Write-Host "[$dt] Displaying final result to PS Console" -ForegroundColor Yellow}
Write-Output $GetResult | Select-Object 'ComputerName', 'OS Caption', 'Manufacturer', 'PowerPlan', '% Processor Performance' | Format-Table -AutoSize -Property *

Write-Host "-------------------------------------------------------------------- `r" 


Write-Host "--------------"
Write-Host "---- Done ----"
Write-Host "--------------"