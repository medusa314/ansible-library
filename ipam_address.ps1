#!powershell
#
# This file is part of Ansible
# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# Written for Dominion Enterprises specific deployment need
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# WANT_JSON
# POWERSHELL_COMMON

# Helper function to parse Ansible JSON arguments from a "file" passed as
# the single argument to the module.
# Example: $params = Parse-Args $args
Function Parse-Args($arguments, $supports_check_mode = $false)
{
    $params = New-Object psobject
    If ($arguments.Length -gt 0)
    {
        $params = Get-Content $arguments[0] | ConvertFrom-Json
    }
    Else {
        $params = $complex_args
    }
    $check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -type "bool" -default $false
    If ($check_mode -and -not $supports_check_mode)
    {
        Exit-Json @{
            skipped = $true
            changed = $false
            msg = "remote module does not support check mode"
        }
    }
    return $params
}
# Helper function to get an "attribute" from a psobject instance in powershell.
# This is a convenience to make getting Members from an object easier and
# slightly more pythonic
# Example: $attr = Get-AnsibleParam $response "code" -default "1"
#Get-AnsibleParam also supports Parameter validation to save you from coding that manually:
#Example: Get-AnsibleParam -obj $params -name "State" -default "Present" -ValidateSet "Present","Absent" -resultobj $resultobj -failifempty $true
#Note that if you use the failifempty option, you do need to specify resultobject as well.
Function Get-AnsibleParam($obj, $name, $default = $null, $resultobj = @{}, $failifempty = $false, $emptyattributefailmessage, $ValidateSet, $ValidateSetErrorMessage, $type = $null, $aliases = @())
{
    # Check if the provided Member $name or aliases exist in $obj and return it or the default.
    try {

        $found = $null
        # First try to find preferred parameter $name
        $aliases = @($name) + $aliases

        # Iterate over aliases to find acceptable Member $name
        foreach ($alias in $aliases) {
            if ($obj.ContainsKey($alias)) {
                $found = $alias
                break
            }
        }

        if ($found -eq $null) {
            throw
        }
        $name = $found

        if ($ValidateSet) {

            if ($ValidateSet -contains ($obj.$name)) {
                $value = $obj.$name
            } else {
                if ($ValidateSetErrorMessage -eq $null) {
                    #Auto-generated error should be sufficient in most use cases
                    $ValidateSetErrorMessage = "Get-AnsibleParam: Argument $name needs to be one of $($ValidateSet -join ",") but was $($obj.$name)."
                }
                Fail-Json -obj $resultobj -message $ValidateSetErrorMessage
            }

        } else {
            $value = $obj.$name
        }

    } catch {
        if ($failifempty -eq $false) {
            $value = $default
        } else {
            if (!$emptyattributefailmessage) {
                $emptyattributefailmessage = "Get-AnsibleParam: Missing required argument: $name"
            }
            Fail-Json -obj $resultobj -message $emptyattributefailmessage
        }

    }

    # If $value -eq $null, the parameter was unspecified by the user (deliberately or not)
    # Please leave $null-values intact, modules need to know if a parameter was specified
    # When $value is already an array, we cannot rely on the null check, as an empty list
    # is seen as null in the check below
    if ($value -ne $null -or $value -is [array]) {
        if ($type -eq "path") {
            # Expand environment variables on path-type
            $value = Expand-Environment($value)
            # Test if a valid path is provided
            if (-not (Test-Path -IsValid $value)) {
                $path_invalid = $true
                # could still be a valid-shaped path with a nonexistent drive letter
                if ($value -match "^\w:") {
                    # rewrite path with a valid drive letter and recheck the shape- this might still fail, eg, a nonexistent non-filesystem PS path
                    if (Test-Path -IsValid $(@(Get-PSDrive -PSProvider Filesystem)[0].Name + $value.Substring(1))) {
                        $path_invalid = $false
                    }
                }
                if ($path_invalid) {
                    Fail-Json -obj $resultobj -message "Get-AnsibleParam: Parameter '$name' has an invalid path '$value' specified."
                }
            }
        } elseif ($type -eq "str") {
            # Convert str types to real Powershell strings
            $value = $value.ToString()
        } elseif ($type -eq "bool") {
            # Convert boolean types to real Powershell booleans
            $value = $value | ConvertTo-Bool
        } elseif ($type -eq "int") {
            # Convert int types to real Powershell integers
            $value = $value -as [int]
        } elseif ($type -eq "float") {
            # Convert float types to real Powershell floats
            $value = $value -as [float]
        } elseif ($type -eq "list") {
            if ($value -is [array]) {
                # Nothing to do
            } elseif ($value -is [string]) {
                # Convert string type to real Powershell array
                $value = $value.Split(",").Trim()
            } else {
                Fail-Json -obj $resultobj -message "Get-AnsibleParam: Parameter '$name' is not a YAML list."
            }
            # , is not a typo, forces it to return as a list when it is empty or only has 1 entry
            return ,$value
        }
    }

    return $value
}

#Alias Get-attr-->Get-AnsibleParam for backwards compat. Only add when needed to ease debugging of scripts
If (!(Get-Alias -Name "Get-attr" -ErrorAction SilentlyContinue))
{
    New-Alias -Name Get-attr -Value Get-AnsibleParam
}
# Helper function to convert a powershell object to JSON to echo it, exiting
# the script
# Example: Exit-Json $result
Function Exit-Json($obj)
{
    # If the provided $obj is undefined, define one to be nice
    If (-not $obj.GetType)
    {
        $obj = @{ }
    }

    if (-not $obj.ContainsKey('changed')) {
        Set-Attr $obj "changed" $false
    }

    echo $obj | ConvertTo-Json -Compress -Depth 99
    Exit
}

# Helper function to add the "msg" property and "failed" property, convert the
# powershell Hashtable to JSON and echo it, exiting the script
# Example: Fail-Json $result "This is the failure message"
Function Fail-Json($obj, $message = $null)
{
    if ($obj -is [hashtable] -or $obj -is [psobject]) {
        # Nothing to do
    } elseif ($obj -is [string] -and $message -eq $null) {
        # If we weren't given 2 args, and the only arg was a string,
        # create a new Hashtable and use the arg as the failure message
        $message = $obj
        $obj = @{ }
    } else {
        # If the first argument is undefined or a different type,
        # make it a Hashtable
        $obj = @{ }
    }

    # Still using Set-Attr for PSObject compatibility
    Set-Attr $obj "msg" $message
    Set-Attr $obj "failed" $true

    if (-not $obj.ContainsKey('changed')) {
        Set-Attr $obj "changed" $false
    }

    echo $obj | ConvertTo-Json -Compress -Depth 99
    Exit 1
}
# Helper function to set an "attribute" on a psobject instance in powershell.
# This is a convenience to make adding Members to the object easier and
# slightly more pythonic
# Example: Set-Attr $result "changed" $true
Function Set-Attr($obj, $name, $value)
{
    # If the provided $obj is undefined, define one to be nice
    If (-not $obj.GetType)
    {
        $obj = @{ }
    }

    Try
    {
        $obj.$name = $value
    }
    Catch
    {
        $obj | Add-Member -Force -MemberType NoteProperty -Name $name -Value $value
    }
}

# Sets results for query
Function Set-QueryResults($ipaddress)
{
	$result.ip = $ipaddress.IpAddress.IPAddressToString
	$result.name = $ipaddress.DeviceName
	$result.description = $ipaddress.Description
	
	$startRange = $ipaddress.IPRange.split("-")[0]
	$endRange = $ipaddress.IPRange.split("-")[1]
	$Range = Get-IpamRange -StartIPAddress $startRange -EndIPAddress $endRange
	$result.rangeName = $Range.Description
	$result.category = $ipaddress.AddressCategory.ToString().ToLower()
		
	# get the subnet to get the custom configuration
	$Subnet = Get-IpamSubnet -NetworkId $Range.NetworkID
	$customConfig = $Subnet.CustomConfiguration -split ";"
	$result.subnetName = $Subnet.Name
	
	foreach ($line in $customConfig)
		{
			if ($line -like "Context*")
			{
				$result.context = ($line -split "=")[1]
			}
			if ($line -like "Site*")
			{
				$result.site = ($line -split "=")[1]
			}
			if ($line -like "Device*")
			{
				$result.device = ($line -split "=")[1]
			}
		}
	$result.startRange = $startRange
	$result.endRange = $endRange
	$result.msg = "query successful"
}

try {
    Import-Module IpamServer
 }
 catch {
     Fail-Json $result "Failed to import IpamServer PowerShell module."
 }
 
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$params = Parse-Args -arguments $args -supports_check_mode $true
$check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -type "bool" -default $false

# these are your module parameters, there are various types which can be
# used to format your parameters. You can also set mandatory parameters
# with -failifempty, set defaults with -default and set choices with
# -validateset.
# IPAM variables
$addressCategory = Get-AnsibleParam -obj $params -name "addressCategory" -type "str" -default "private" -validateset "public","private"
$addressFamily = Get-AnsibleParam -obj $params -name "addressFamily" -type "str" -default "IPv4" -validateset "IPv4","IPv6"
$deviceType = Get-AnsibleParam -obj $params -name "deviceType" -type "str" -default "Host" -validateset "Host","Load balancer","Firewall","Routers","Printer","Switch","VM","VPN","Wireless AP","Wireless controller"
$service = Get-AnsibleParam -obj $params -name "service" -type "str" -default "IPAM" -validateset "IPAM","MS DHCP","Non-MS DHCP","Others","VMM"
$ipAddressState = Get-AnsibleParam -obj $params -name "ipAddressState" -type "str" -default "In-Use" -validateset "In-Use","Inactive","Reserved"
$instance = Get-AnsibleParam -obj $params -name "instance" -type "str" -default "localhost"
$assignmentType = Get-AnsibleParam -obj $params -name "type" -type "str" -default "Static" -validateset "Static","Dynamic"
#
$state = Get-AnsibleParam -obj $params -name "state" -type "str" -default "present" -validateset "absent","present","query","create","modify"
#
$startRange = Get-AnsibleParam -obj $params -name "startRange" -type "str"
$endRange = Get-AnsibleParam -obj $params -name "endRange" -type "str"
$context = Get-AnsibleParam -obj $params -name "context" -type "str"
$site = Get-AnsibleParam -obj $params -name "site" -type "str"
$ip = Get-AnsibleParam -obj $params -name "ip" -type "str"
$hostname = Get-AnsibleParam -obj $params -name "hostname" -type "str"
#
$description = Get-AnsibleParam -obj $params -name "description" -type "str" -default "host"
#
$result = @{
    changed = $false
}

# code goes here
# if state is query, check if the IP address exists in IPAM
if($state -eq "query")
{
	if ($ip)
	{
		try
		{
			$queryIP = Get-IpamAddress -IpAddress $ip
		}
		
		catch [System.Management.Automation.RuntimeException]
		{
			$result.msg = "Unable to find ip $ip"
			Exit-Json -obj $result
		}
		Set-QueryResults -ipaddress $queryIP
	}
	elseif($hostname)
	{
		try
		{
			$queryIP = Get-IpamAddress -AddressFamily IPv4 | Where-Object -FilterScript {$_.Description -eq $hostname -or $_.Name -eq $hostname}
		}
		catch [System.Management.Automation.RuntimeException]
		{
			$result.msg = "Unable to find host $hostname by name"
			Exit-Json -obj $result
		}
		Set-QueryResults -ipaddress $queryIP
	}
	else
	{
		$result.msg = "No query parameter.  Enter ip or hostname"
		Exit-Json -obj $result
	}
}
# If state is present, find a free IP address
elseif($state -eq "present")
{
	if ($startRange -and $endRange)
	{
		try
		{
			$Range = Get-IpamRange -StartIPAddress $startRange -EndIPAddress $endRange
			$result.rangeName = $Range.Description
			$availableIP = $Range.AssignedAddresses - $Range.UtilizedAddresses
		}
		
		catch [System.Management.Automation.RuntimeException]
		{
			$result.msg = "Failed to retrieve provided range start $startRange end $endRange"
			Exit-Json -obj $result
		}
		if ($Range.PercentageUtilized -eq 100)
		{
			Fail-Json $result "Range has no available IPs."
		}
		else
		{
			$available = $Range | Find-IpamFreeAddress -NumAddress $availableIP -TestReachability
			
			Foreach($a in $available)
			{
				if($a.PingStatus -eq "Reply")
				{
					continue
				}
				else
				{
					$ipResult = $a.Address
					break
				}		
			}
			try
			{
				$result.ip = $ipResult
				$Subnet = Get-IpamSubnet -NetworkId $Range.NetworkID
				$customConfig = $Subnet.CustomConfiguration -split ";"
				$result.subnetName = $Subnet.Name
				$result.rangeName = $Range.Description
				foreach ($line in $customConfig)
				{
					if ($line -like "Context*")
					{
						$result.context = ($line -split "=")[1]
					}
					if ($line -like "Site*")
					{
						$result.site = ($line -split "=")[1]
					}
					if ($line -like "Device*")
					{
						$result.device = ($line -split "=")[1]
					}
				}			
			}
			catch [System.Management.Automation.RuntimeException]
			{
				Fail-Json $result "Range has no available IPs. **  There are reachable IPs not in IPAM **"
			}
		}
	}
	elseif($addressCategory -eq "public")
	{
	   $result.category = $addressCategory
		if ($context -and $site)
		{
			try
			{
				$Subnets = Get-IpamSubnet -AddressFamily $addressFamily | where {$_.CustomConfiguration -Like "*Context=$context;Site=$site*"} | where-object {$_.Owner -eq "DE"} | Sort-object PercentageUtilized
			}
			
			catch [System.Management.Automation.RuntimeException]
			{
				$result.msg = "Failed to search $addressCategory with site $site and context $context"
				Exit-Json -obj $result
			}
			
			if ($Subnets[0].PercentageUtilized -lt 100)
			{
				try
				{
					$Ranges = Get-IpamRange -MappingToSubnet $Subnets[0] | Sort-object PercentageUtilized
				}
				
				catch [System.Management.Automation.RuntimeException]
				{
					$result.msg = "Failed to retrieve ranges for subnet"
					Exit-Json -obj $result
				}
				if ($Ranges[0].PercentageUtilized -lt 100)
				{
					$result.ip = $Ranges[0] | Find-IpamFreeAddress | ForEach-Object {$_.Address}
					$result.subnetName = $Subnets[0].Name
					$result.rangeName = $Ranges[0].Description
					$startRange = $Ranges[0].StartIPAddress
					$endRange = $Ranges[0].EndIPAddress
					
					$Subnet = Get-IpamSubnet -NetworkId $Ranges[0].NetworkID
					$customConfig = $Subnets[0].CustomConfiguration -split ";"
					foreach ($line in $customConfig)
					{
						if ($line -like "Context*")
						{
							$result.context = ($line -split "=")[1]
						}
						if ($line -like "Site*")
						{
							$result.site = ($line -split "=")[1]
						}
						if ($line -like "Device*")
						{
							$result.device = ($line -split "=")[1]
						}
					}
				}
				else
				{
					Fail-Json $result "Failed to find range with an available IP."
				}
			}
			else
			{
				Fail-Json $result "No available IPs."
			}
		}
		else
		{
			Fail-Json $result "Missing parameters to search - site and firewall context required."
		}
	}
	else
	{
		$result.startRange = $startRange
		$result.endRange = $endRange
		Fail-Json $result "Missing parameter(s) to assign IP address"
	}
	$result.startRange = $startRange
	$result.endRange = $endRange
}
# remove IP from IPAM
elseif($state -eq "absent")
{
	try
	{
		Get-IpamAddress -IpAddress $ip | Remove-IpamAddress -Force
	}
	
	catch [System.Management.Automation.RuntimeException]
	{
		$result.msg = "Unable to remove ip $ip"
		Exit-Json -obj $result
	}
	$result.msg = "removed ip $ip"
	$result.ip = $ip
}
# create IP in IPAM
elseif($state -eq "create")
{
	try
	{
		Add-IpamAddress -IpAddress $ip -Description $description -ManagedByService $service -ServiceInstance $instance  -DeviceType $deviceType -IpAddressState $ipAddressState  -AssignmentType $assignmentType
	}
	
	catch [System.Management.Automation.RuntimeException]
	{
		$result.msg = "Unable to create ip $ip"
		Exit-Json -obj $result
	}
	$result.ip = $ip
	$result.description = $description
	$result.msg = "Created $ip"
}
# create IP in IPAM
elseif($state -eq "modify")
{
	try
	{
		Get-IpamAddress -IpAddress $ip | Set-IpamAddress -Description $description -NewManagedByService $service -NewServiceInstance $instance -DeviceType $deviceType -IpAddressState $ipAddressState  -AssignmentType $assignmentType
	}
	
	catch [System.Management.Automation.RuntimeException]
	{
		$result.msg = "Unable to modify ip $ip"
		Exit-Json -obj $result
	}
	$result.ip = $ip
	$result.description = $description
	$result.msg = "Modified $ip"
}
else
{
	Fail-Json $result "Invalid state"
}

# result objects
$result.changed = $true
$result.state = $state

Exit-Json -obj $result