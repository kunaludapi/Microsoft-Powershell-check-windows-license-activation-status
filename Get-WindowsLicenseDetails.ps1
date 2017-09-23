#
#requires -version 4
<#
.SYNOPSIS
    Get windows office and OS licensing information.
.DESCRIPTION
    The Get-WindowsLicenseDetails list Windows licening activation details as well as Microsoft software such as office activation details.
.PARAMETER ComputerName
    Prompts for Computername or IP address. CN and Name can be used as an alias, If no information is provided, this will take local computer hostname as argument. 
.PARAMETER TextFile
    This syntax asks for valid text file name and it is mandatory parameter. Text file must contain computername or IP address in list.
.PARAMETER Protocol
    There are two protocols can be used while connecting to remote computer, This is optional parameter, first is DCOM which is default and need not to mention, Default will work in all scenario. Another protocol is WSman require PS remoting need to be enabled. 
.PARAMETER Credential
    This is optional parameter, Popups for active directory username password, supply domain admin user account to connect remote server.
.INPUTS
    [System.String]
.OUTPUTS
    [System.Object]
.NOTES
    Version:        1.0
    Author:         Kunal Udapi
    Creation Date:  20 September 2017
    Purpose/Change: Get windows office and OS licensing information.
    Useful URLs: http://vcloud-lab.com
.EXAMPLE
    PS C:\>.\Get-WindowsLicenseDetails -ComputerName Server01,Server02,Server03 

    This list windows license details from provided computernames, and use wmi (DCom) protocol. This used currently logged in user account.
.EXAMPLE
    PS C:\>.\Get-WindowsLicenseDetails -ComputerName Server01 -Protocol Wsman -Crdential

    This list windows license details from provided computernames, and use wsman (winrm) protocol is used to connect remote computers, by providing credential parameter it will ask for username and password to connect remote computer.
.EXAMPLE
    PS C:\>.\Get-WindowsLicenseDetails -TextFile C:\Temp\list.txt

    Text file has computer name list, information is collected using wmi (DCom) protocol, this will try to connect remote computers with currently logged in user account.
.EXAMPLE
    PS C:\>.\Get-WindowsLicenseDetails -TextFile C:\Temp\list.txt -Protocol Wsman -Crdential

    Text file has computer name list, information is collected using wsman (winrm) protocol, It will pop ups for username password.

#>
[CmdletBinding(SupportsShouldProcess=$True,
    ConfirmImpact='Medium',
    HelpURI='http://vcloud-lab.com',
    DefaultParameterSetName='CN')]
Param
(
    [parameter(Position=0, Mandatory=$True, ParameterSetName='File', ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true, HelpMessage='Type valid text file pathname')]
    [ValidateScript({
        If(Test-Path $_){$true}else{throw "Invalid path given: $_"}
    })]
    [alias('File')]
    [string]$TextFile,
    
    [parameter(Position=0, Mandatory=$false, ParameterSetName='CN', ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true, HelpMessage='Type valid text file pathname')]
    [alias('CN', 'Name')]
    [String[]]$ComputerName = $env:COMPUTERNAME,

    [parameter(ParameterSetName = 'File', Position=1, Mandatory=$false, HelpMessage='Type valid text file pathname')]
    [parameter(ParameterSetName = 'CN', Position=0, Mandatory=$false)]
    [ValidateSet('Dcom','Default','Wsman')]
    [String]$Protocol = 'Dcom',

    [parameter(ParameterSetName = 'File', Position=2, Mandatory=$false)]
    [parameter(ParameterSetName = 'CN', Position=2, Mandatory=$false)]    
    [Switch]$Credential
)
Begin {
    #[String[]]$ComputerName = $env:COMPUTERNAME
    if ($Credential.IsPresent -eq $True) {
        $Cred = Get-Credential -Message 'Type domain credentials to connect remote Server' -UserName (WhoAmI)
    }
    $CimSessionOptions = New-CimSessionOption -Protocol $Protocol
    $Query = "Select * from  SoftwareLicensingProduct Where PartialProductKey LIKE '%'"
}
Process {
    switch ($PsCmdlet.ParameterSetName) {
        'CN' {
            Break
        }
        'File' {
            $ComputerName = Get-Content $TextFile
            Break
        }
    }
    foreach ($Computer in $ComputerName) {
        if (-not(Test-Connection -ComputerName $Computer -Count 2 -Quiet)) {
            Write-Host -BackgroundColor DarkYellow ([char]8734) -NoNewline
            Write-Host " $Computer is not reachable, ICMP may be disabled...."
            #Break
        }
        else {
            Write-Host -BackgroundColor DarkGreen ([char]8730) -NoNewline
            Write-Host " $Computer is reachable connecting...."
        }
        try {
            if ($Credential.IsPresent -eq $True) {
                $Cimsession = New-CimSession -Name $Computer -ComputerName $Computer -SessionOption $CimSessionOptions -Credential $Cred -ErrorAction Stop
            }
            else {
                $Cimsession = New-CimSession -Name $Computer -ComputerName $Computer -SessionOption $CimSessionOptions  -ErrorAction Stop
            }
            $LicenseInfo = Get-CimInstance -Query $Query -CimSession $Cimsession -ErrorAction Stop 
            Switch ($LicenseInfo.LicenseStatus) {
                0 {$LicenseStatus = 'Unlicensed'; Break}
                1 {$LicenseStatus = 'Licensed'; Break}
                2 {$LicenseStatus = 'OOBGrace'; Break}
                3 {$LicenseStatus = 'OOTGrace'; Break}
                4 {$LicenseStatus = 'NonGenuineGrace'; Break}
                5 {$LicenseStatus = 'Notification'; Break}
                6 {$LicenseStatus = 'ExtendedGrace'; Break}
            } 
            $LicenseInfo | Select-Object PSComputerName, Name, @{N = 'LicenseStatus'; E={$LicenseStatus}},AutomaticVMActivationLastActivationTime, Description, GenuineStatus, GracePeriodRemaining, LicenseFamily, PartialProductKey, RemainingSkuReArmCount, IsKeyManagementServiceMachine #, ApplicationID
            }
        catch {
            Write-Host -BackgroundColor DarkRed ([char]215) -NoNewline
            Write-Host " Cannot fetch information from $Computer" 
        }
    }
}