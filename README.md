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
