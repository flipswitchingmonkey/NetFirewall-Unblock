<#
.SYNOPSIS
Lists the applications that were blocked and offers to create Allow rules
.DESCRIPTION
The script takes history amount of event messages from the Security Event Log where Firewall rules caused packets in a certain direction to be dropped.
The blocked applications are then shown as a list for the user to select. Upon selection an Allow rule will be created if it does not yet exist, or an existing Block rule will be changed to Allow.
.PARAMETER history
The number of event log messages from the top that are being evaluated. Defaults to 1000. Higher values take longer to evaluate.
.PARAMETER direction
Evaluate only Inbound or Outbound directed messages. Defaults to Outbound.
.PARAMETER checkIfExists
Does a primitive check if there is a NetFirewallApplicationFilter entry for the application in question. 
If there is then there is a good chance that a rule for this application exists and the entry will be marked with (*).
Has no immediate effect other than informational purposes.
.EXAMPLE
NetFirewall-Unblock.ps1
NetFirewall-Unblock.ps1 -history 400 -direction Inbound -checkIfExists No
.NOTES
You need to run this function with administrative rights to be able to modify Firewall rules.
Author: Michael Auerswald <michael@flipswitchingmonkey.com>
.LINK
http://www.flipswitchingmonkey.com
#>

param(
    [Parameter(Mandatory=$false)]
    $history = 1000,

    [Parameter(Mandatory=$false)]
    [ValidateSet('Inbound','Outbound')]
    $direction = "Outbound",

    [ValidateSet('Yes','No')]
    $checkIfExists = "Yes"

)

# Directions are not showing up as "Inbound" or "Outbound" but as what I presume are String identifiers?
# Inbound %%14592
# Outbound %%14593

# Build System Assembly in order to call Kernel32:QueryDosDevice. 
$DynAssembly = New-Object System.Reflection.AssemblyName('SysUtils')
$AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('SysUtils', $False)
 
# Define [Kernel32]::QueryDosDevice method
$TypeBuilder = $ModuleBuilder.DefineType('Kernel32', 'Public, Class')
$PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('QueryDosDevice', 'kernel32.dll', ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static), [Reflection.CallingConventions]::Standard, [UInt32], [Type[]]@([String], [Text.StringBuilder], [UInt32]), [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
$SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('kernel32.dll'), [Reflection.FieldInfo[]]@($SetLastError), @($true))
$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
$Kernel32 = $TypeBuilder.CreateType()
 
$Max = 65536
$StringBuilder = New-Object System.Text.StringBuilder($Max)

$DriveMapping = @{}

Get-WmiObject Win32_Volume | ? { $_.DriveLetter } | % {
    $ReturnLength = $Kernel32::QueryDosDevice($_.DriveLetter, $StringBuilder, $Max)
 
    if ($ReturnLength)
    {
        $DriveMapping.Add($StringBuilder.ToString(), $_.DriveLetter)
    }
}


$mainFunction = {
    if ($direction -eq "Outbound")
    {
        $directionNumeric = "%%14593"
    }
    else
    {
        $directionNumeric = "%%14592"
    }
    $action = "Allow"
    $ArrList = [System.Collections.ArrayList]@()

    $output = Get-EventLog -LogName Security -Newest $history -EntryType FailureAudit | Where-Object -Property ReplacementStrings -eq $directionNumeric | % {
        if ($_.ReplacementStrings[1].length -gt 3)  # we'll ignore entries that have no program path data (they show up as "-")
        {
            $ArrList.Add($_.ReplacementStrings[1])  # fetch the application path
        }
    }
    #$ArrList.Sort()  # needs to be sorted for Get-Unique to work (but we use select -unique now so it doesn't matter)
    $uniques = @( $ArrList.ToArray() | select -Unique )  # force result to be an array even if there is only one result

    "`nRecently Blocked {0} Processes: (based on {1} last event log entries)" -f $direction, $history
    For($counter=0; $counter -lt $uniques.Length; $counter++)
    {
        # sometime paths are not stored as file system paths but rather as physical paths. firewall rules can't deal with those so we have to translate them
        if ($uniques[$counter] -like "\device\harddiskvolume*") 
        {
            $matchresult = $uniques[$counter] -match "\\device\\harddiskvolume.?"
            if ($matchresult -eq "True") {
                $driveletter = $DriveMapping.($matches[0])
            }
            else
            {
                $driveletter = "?:"
            }
            #$driveLetter = Get-Volume -FilePath ($uniques[$counter] -as [string])
            $path = $uniques[$counter] -replace "\\device\\harddiskvolume.?\\"
            #$fullpath =  (Join-Path -Path ($driveLetter.DriveLetter + ':') -Childpath ($path -as [string]))
            $fullpath =  (Join-Path -Path ($driveLetter) -Childpath ($path -as [string]))
            $uniques[$counter] = $fullpath  # in case we have translated the path, replace the original with the translated version
        }
        else
        {
            $fullpath = $uniques[$counter]
        }
        $addedText = ""
        if($checkIfExists -like "Yes")
        {
            try {
                $lookup = Get-NetFirewallApplicationFilter -Program $fullpath -PolicyStore ActiveStore -ErrorAction Stop
                if ($lookup -ne $null)
                {
                    $addedText = "(*)"
                }
            }
            catch {
            
            }
        }
        "{0}: {1}{2}" -f $counter, $addedText, $fullpath
    }

    "Select entry to Allow: (0-{0} / enter to refresh / x to exit / d to switch direction / h### change number of entries )" -f ($counter-1)
}

# we'll just loop through the script indefinitely until either x or ctrl-c are pressed
while ($true)
{
    .$mainFunction
    $x = $host.UI.ReadLine()
    if ($x -like "x")
    {
        exit
    }
    elseif ($x -like "d")
    {
        if ($direction -eq "Outbound")
        {
            $direction = "Inbound"
        }
        else
        {
            $direction = "Outbound"
        }
    }
    elseif ($x.Length -gt 1 -and $x.Substring(0,1) -like "h")
    {
        Try
        {
            $history = [convert]::ToInt32($x.Substring(1), 10)
        }
        Catch
        {
            Write-Host "invalid command: {0}" -f $x
        }
    }
    elseif ($x -like "")
    {
        # do nothing, repeat
    }
    else
    {
        $pName = Split-Path $uniques[$x] -Leaf  # the filename will be used as the DisplayName for the new rule
        try {
            $lookup = Get-NetFirewallApplicationFilter -Program $uniques[$x] -PolicyStore ActiveStore  -ErrorAction Stop | Get-NetFirewallRule -Direction $direction -PolicyStore ActiveStore -ErrorAction Stop
            Set-NetFirewallRule -Action $action -Program $uniques[$x] -Name $lookup.Name -Direction $direction
            Get-NetFirewallRule -PolicyStore ActiveStore -Name $lookup.name
        }
        catch {
            "No rule found for {0}" -f $uniques[$x]
            "Creating Outbound Allow rule for {0}" -f $uniques[$x]
            New-NetFirewallRule -Action $action -Program $uniques[$x] -DisplayName $pName -Direction $direction
        }
    }
} # end while
