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
# Sets results for query.  Assumes a valid Subnet object is passed as a parameter.
Function Set-SubnetResults($subnet)
{
	$s = @{}
	$s.name = $subnet.Name
	$s.networkID = $subnet.NetworkId
	$s.overlap = $subnet.Overlapping
	if($subnet.Description)
	{
		$s.description = $subnet.Description
	}
	$s.totalAddresses = $subnet.TotalAddresses
	if($subnet.VlanID)
	{
		$s.vlan = $subnet.VlanID
	}
	if($subnet.CustomerAddressSpace)
	{
		$s.vlan = $subnet.CustomerAddressSpace
	}
	if($subnet.Owner)
	{
		$s.owner = $subnet.Owner
	}
	if($subnet.AssignedAddresses)
	{
		$addresses = @{}
		$addresses.assigned = $subnet.AssignedAddresses
		$addresses.percentageUtilized = $subnet.PercentageUtilized
		$addresses.utilized = $subnet.UtilizedAddresses
		$s.addresses = $addresses
	}
	if($subnet.VmmLogicalNetwork)
	{
		$s.vmmLogicalNetwork = $subnet.VmmLogicalNetwork
	}
	if($subnet.AddressSpace)
	{
		$s.addressSpace = $subnet.AddressSpace
	}
	if($subnet.NetworkSite)
	{
		$s.networkSite = $subnet.NetworkSite
	}
	if($subnet.NetworkType)
	{
		$s.networkType = $subnet.NetworkType.ToString()
	}
	
	if($subnet.CustomConfiguration)
	{
		$customConfig = $subnet.CustomConfiguration -split ";"
		$c = @{}
		
		foreach ($line in $customConfig)
		{
			$key = ($line -split "=")[0]
			$value = ($line -split "=")[1]
			if ($key -ne "")
			{
				$c.$key = $value
			}
		}
		$s.customConfiguration = $c
	}
	return $s
}
Function Set-RangeResults($range)
{
	$r = @{}
	if($range.Description)
	{
		$r.description = $range.Description
	}
	$r.assignmentType = $range.AssignmentType.ToString()
	$r.managedByService = $range.ManagedByService
	
	if($range.AssignedAddresses)
	{
		$addresses = @{}
		$addresses.assigned = $range.AssignedAddresses
		$addresses.percentageUtilized = $range.PercentageUtilized
		$addresses.utilized = $range.UtilizedAddresses
		$r.addresses = $addresses
	}
	if($range.DhcpScopeName)
	{
		$d = @{}
		$d.scopeName = $range.DhcpScopeName	
		$d.serverName = $range.DhcpServerName
		if($range.DnsSuffixes)
		{
			$d.dnsSuffixes = $range.DnsSuffixes
		}
		if($range.ExclusionRanges)
		{
			$d.exclusionRanges = $range.ExclusionRanges
		}
		if($range.Gateway)
		{
			$d.gateway = $range.Gateway
		}
		if($range.AssociatedReverseLookupZone)
		{
			$d.AssociatedReverseLookupZone = $range.AssociatedReverseLookupZone
		}
		if($range.DnsServers)
		{
			$d.DnsServers = $range.DnsServers
		}
		if($range.WinsServers)
		{
			$d.WinsServers = $range.WinsServers
		}
		$r.dhcp = $d
	}
	
	if($range.CustomConfiguration)
	{
		$customConfig = $range.CustomConfiguration -split ";"
		$c = @{}
		
		foreach ($line in $customConfig)
		{
			$key = ($line -split "=")[0]
			$value = ($line -split "=")[1]
			if ($key -ne "")
			{
				$c.$key = $value
			}
		}
		$r.customConfiguration = $c
	}
	return $r
}
# Sets results for query
Function Set-QueryResults($ipaddress)
{
	$rip = @{}
	$rip.ip = $ipaddress.IpAddress.IPAddressToString
	if($ipaddress.Description)
	{
		$rip.description = $ipaddress.Description
	}
	if($ipaddress.DeviceName)
	{
		$rip.name = $ipaddress.DeviceName
	}
	if($ipaddress.AddressCategory)
	{
		$rip.category = $ipaddress.AddressCategory.ToString().ToLower()
		
	}
	try
	{
		# get the range configuration
		$startRange = $ipaddress.IPRange.split("-")[0]
		$endRange = $ipaddress.IPRange.split("-")[1]
		$Range = Get-IpamRange -StartIPAddress $startRange -EndIPAddress $endRange
		$ran = Set-RangeResults($Range)
		$rip.range = $ran
		$rip.startRange = $startRange
		$rip.endRange = $endRange
		# get the subnet configuration
		$Subnet = Get-IpamSubnet -NetworkId $Range.NetworkID
		$sub = Set-SubnetResults($Subnet)
		$rip.subnet = $sub
		$rip.msg = "query successful"
	}	
	catch [System.Management.Automation.RuntimeException]
	{
		$rip.msg = "unmapped IP"
	}
	return $rip
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
$state = Get-AnsibleParam -obj $params -name "state" -type "str" -default "present" -validateset "absent","present","query"
#
$startRange = Get-AnsibleParam -obj $params -name "startRange" -type "str"
$endRange = Get-AnsibleParam -obj $params -name "endRange" -type "str"
$customConfiguration = Get-AnsibleParam -obj $params -name "customConfiguration" -type "str"
$ip = Get-AnsibleParam -obj $params -name "ip" -type "str"
$hostname = Get-AnsibleParam -obj $params -name "hostname" -type "str"
$numberOfAddresses = Get-AnsibleParam -obj $params -name "numberOfAddresses" -type "int" -default 1
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
		$resultList = @()
		$resultList += Set-QueryResults -ipaddress $queryIP
		$result.ips = $resultList
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
		$resultList = @()
		$resultList += Set-QueryResults -ipaddress $queryIP
		$result.ips = $resultList
	}
	else
	{
		$result.msg = "No query parameter.  Enter ip or hostname"
		Exit-Json -obj $result
	}
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
	$result.changed = $true
}
else
{
	$ips = @()
	$numFound = 0
	$exists = $false
	if($ip)
	{
		# modify an existing IP
		try
		{
			Get-IpamAddress -IpAddress $ip | Set-IpamAddress -Description $description -NewManagedByService $service -NewServiceInstance $instance -DeviceType $deviceType -IpAddressState $ipAddressState  -AssignmentType $assignmentType
			$exists = $true
			#get results after the modification
			$queryIP = Get-IpamAddress -IpAddress $ip
			$resultList = @()
			$resultList += Set-QueryResults -ipaddress $queryIP
			$result.ips = $resultList
			$result.msg = "Modified $ip"
			$result.changed = $true
			Exit-Json -obj $result
		}
		catch [System.Management.Automation.RuntimeException]
		{
			$exists = $false
		}
		
		#add the IP address
		try
		{
			Add-IpamAddress -IpAddress $ip -Description $description -ManagedByService $service -ServiceInstance $instance  -DeviceType $deviceType -IpAddressState $ipAddressState  -AssignmentType $assignmentType
			$queryIP = Get-IpamAddress -IpAddress $ip
			$resultList = @()
			$resultList += Set-QueryResults -ipaddress $queryIP
			$result.ips = $resultList
			$result.msg = "Created $ip"
			$result.changed = $true
			
		}
		catch [System.Management.Automation.RuntimeException]
		{
			$result.msg = "Unable to create ip $ip"
			Exit-Json -obj $result
		}
	}
	elseif ($startRange -and $endRange)
	{
		try
		{
			$Range = Get-IpamRange -StartIPAddress $startRange -EndIPAddress $endRange
			$availableIP = $Range.AssignedAddresses - $Range.UtilizedAddresses
		}
		
		catch [System.Management.Automation.RuntimeException]
		{
			$result.msg = "Failed to retrieve provided range start $startRange end $endRange"
			Exit-Json -obj $result
		}
		if($availableIP -le $numberOfAddresses)
		{
			Fail-Json $result "Not enough available IPs"
		}
		if ($Range.PercentageUtilized -eq 100)
		{
			Fail-Json $result "Range has no available IPs."
		}
		else
		{
			try
			{
				$available = $Range | Find-IpamFreeAddress -NumAddress $availableIP -TestReachability
				
				foreach($a in $available)
				{
					if($a.PingStatus -eq "Reply")
					{
						continue
					}
					else
					{
						$ips += $a.Address
						$numFound += 1
						if($numFound -eq $numberOfAddresses)
						{
							break
						}
						else
						{
							continue
						}
					}		
				}
				$result.ips = $ips		
			}
			catch [System.Management.Automation.RuntimeException]
			{
				Fail-Json $result "Range does not have enough available IPs. **  There mmay be reachable IPs not in IPAM **"
			}
		}
	}
	elseif($addressCategory -and $customConfiguration)
	{
		$Subnets = @()
	   $result.category = $addressCategory
		try
		{
			$Blocks = Get-IpamBlock -AddressFamily $addressFamily -AddressCategory $addressCategory
			if($Blocks.Count -ge 1)
			{
				foreach($block in $Blocks)
				{
					try
					{
						$Subnets += Get-IpamSubnet -MappingToBlock $block | where {$_.CustomConfiguration -Like "*$customConfiguration*"} | Sort-object PercentageUtilized
					}
					catch [System.Management.Automation.RuntimeException]
					{
						continue
					}
				}
			}
			elseif($Blocks.Count -eq 1)
			{
				$Subnets += Get-IpamSubnet -MappingToBlock $Blocks | where {$_.CustomConfiguration -Like "*$customConfiguration*"}
			}
			else
			{
				$result.msg = "Unable to find $addressCategory $addressFamily subnets with $customConfiguration"
				Exit-Json -obj $result
			}
		}
		catch [System.Management.Automation.RuntimeException]
		{
			$result.msg = "Unable to find $addressCategory $addressFamily subnets with $customConfiguration"
			Exit-Json -obj $result
		}
	   	
	   	foreach($sub in $Subnets)
	   	{
	   		if ($sub.PercentageUtilized -lt 100 -and $sub.AssignedAddresses -ge 0)
	   		{
	   			$Ranges = Get-IpamRange -MappingToSubnet $sub | Sort-object PercentageUtilized
	   			foreach($r in $Ranges)
	   			{
	   				if($r.PercentageUtilized -lt 100)
	   				{
	   					$Range = $r
	   					$Subnet = $sub
	   					break
	   				}
	   			}
	   			break
	   		}
	   	}
        try
        {
			$availableIP = $Range.AssignedAddresses - $Range.UtilizedAddresses
			$startRange = $Range.StartIPAddress
			$endRange = $Range.EndIPAddress
			
			$available = $Range | Find-IpamFreeAddress -NumAddress $availableIP -TestReachability
		
			foreach($a in $available)
			{
				if($a.PingStatus -eq "Reply")
				{
					continue
				}
				else
				{
					$ips += $a.Address
					$numFound += 1
					if($numFound -eq $numberOfAddresses)
					{
						break
					}
					else
					{
						continue
					}
				}		
			}
			$result.ips = $ips
		}
		catch [System.Management.Automation.RuntimeException]
		{
			$result.msg = "Unable to find $addressCategory $addressFamily subnets with $customConfiguration"
			Exit-Json -obj $result
		}
	}
	else
	{
		$result.startRange = $startRange
		$result.endRange = $endRange
		Fail-Json $result "Missing parameter(s) to configure IP address in IPAM"
	}
}

# result objects
$result.state = $state

Exit-Json -obj $result