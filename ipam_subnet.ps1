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
Function Set-QueryResults($subnet)
{
	$s = @{}
	$s.name = $subnet.Name
	$s.networkID = $subnet.NetworkId
	$s.overlap = $subnet.Overlapping
	$s.totalAddresses = $subnet.TotalAddresses
	if($subnet.Description)
	{
		$s.description = $subnet.Description
	}
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
$addressCategory = Get-AnsibleParam -obj $params -name "addressCategory" -type "str" -validateset "public","private"
$addressFamily = Get-AnsibleParam -obj $params -name "addressFamily" -type "str" -default "IPv4" -validateset "IPv4","IPv6"
#
$state = Get-AnsibleParam -obj $params -name "state" -type "str" -default "present" -validateset "absent","present","query","list"
#
$customConfiguration = Get-AnsibleParam -obj $params -name "customConfiguration" -type "str" 
$subnetName = Get-AnsibleParam -obj $params -name "subnetName" -type "str"
$network = Get-AnsibleParam -obj $params -name "network" -type "str"
#
$vlan = Get-AnsibleParam -obj $params -name "vlan" -type "str"
$description = Get-AnsibleParam -obj $params -name "description" -type "str"
$owner = Get-AnsibleParam -obj $params -name "owner" -type "str"
$networkType = Get-AnsibleParam -obj $params -name "networkType" -type "str"
$addressSpace = Get-AnsibleParam -obj $params -name "addressSpace" -type "str"
$newNetwork = Get-AnsibleParam -obj $params -name "newNetwork" -type "str"
#
$result = @{
    changed = $false
}

# if state is query, check if the subnet exists in IPAM
if($state -eq "query")
{
	$resultList = @()
	#search by subnet name
	if($subnetName)
	{
		try
		{
			$Subnets = Get-IpamSubnet -AddressFamily $addressFamily | where {$_.Description -eq "$subnetName"}
		}
		
		catch [System.Management.Automation.RuntimeException]
		{
			$result.msg = "Unable to find subnet by name $subnetName"
			Exit-Json -obj $result
		}
		
	}
	#search by subnet id
	elseif($network)
	{
		try
		{
			$Subnets = Get-IpamSubnet -NetworkId $network
		}
		
		catch [System.Management.Automation.RuntimeException]
		{
			$result.msg = "Unable to find subnet by networkId $network"
			Exit-Json -obj $result
		}
	}
	else
	{
		Fail-Json $result "Missing parameter for query"
	}
	
	if(!$Subnets)
	{
		$result.msg = "Unable to find matching subnets"
		Exit-Json -obj $result
	}
	# set the query results to return
	foreach ($subnet in $Subnets)
	{
		$sub = Set-QueryResults -subnet $subnet
		$resultList += $sub
	}
	$result.changed = $false
	$result.subnets = $resultList
	
}
# If state is list, return a list of the subnets
elseif($state -eq "list")
{
	$resultList = @()
	$subnetList = @()
	# get all subnets matching a custom configuration string and address category
	if($customConfiguration -and $addressCategory)
	{
		try
		{
			$Blocks = Get-IpamBlock -AddressFamily $addressFamily -AddressCategory $addressCategory
			if($Blocks.Count -ge 1)
			{
				foreach($block in $Blocks)
				{
					try
					{
						$subnetList += Get-IpamSubnet -MappingToBlock $block | where {$_.CustomConfiguration -Like "*$customConfiguration*"}
					}
					catch [System.Management.Automation.RuntimeException]
					{
						continue
					}
				}
			}
			elseif($Blocks.Count -eq 1)
			{
				$subnetList += Get-IpamSubnet -MappingToBlock $Blocks | where {$_.CustomConfiguration -Like "*$customConfiguration*"}
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
	}
	# get all subnets matching a custom configuration for an address family
	elseif($customConfiguration)
	{
		try
		{
			$Blocks = Get-IpamBlock -AddressFamily $addressFamily
			if($Blocks.Count -ge 1)
			{
				foreach($block in $Blocks)
				{
					try
					{
						$subnetList += Get-IpamSubnet -MappingToBlock $block | where {$_.CustomConfiguration -Like "*$customConfiguration*"}
					}
					catch [System.Management.Automation.RuntimeException]
					{
						continue
					}
				}
			}
			elseif($Blocks.Count -eq 1)
			{
				$subnetList += Get-IpamSubnet -MappingToBlock $Blocks | where {$_.CustomConfiguration -Like "*$customConfiguration*"}
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
	}
	# get all the subnets
	else
	{
		try
		{
			$Blocks = Get-IpamBlock -AddressFamily $addressFamily -AddressCategory $addressCategory
			if($Blocks.Count -ge 1)
			{
				foreach($block in $Blocks)
				{
					$subnetList += Get-IpamSubnet -AddressFamily $addressFamily 
				}
			}
			elseif($Blocks.Count -eq 1)
			{
				$subnetList += Get-IpamSubnet -AddressFamily $addressFamily
			}
			else
			{
				$result.msg = "Unable to find $addressCategory $addressFamily subnets"
				Exit-Json -obj $result
			}
		}
		catch [System.Management.Automation.RuntimeException]
		{
			$result.msg = "Unable to find $addressCategory $addressFamily subnets"
			Exit-Json -obj $result
		}
	}
	# fill in the results
	foreach ($subnet in $subnetList)
	{
		$sub = Set-QueryResults -subnet $subnet
		$resultList += $sub
	}
	$result.numberOfSubnets = $subnetList.Count
	$result.changed = $false
	$result.subnets = $resultList
}
#remove a subnet
elseif($state -eq "absent")
{
	try
	{
		Remove-IpamSubnet -NetworkId $network -DeleteAssociatedRanges -DeleteAssociatedAddresses -Force
	}
	catch [System.Management.Automation.RuntimeException]
	{
		Fail-Json $result  "unable to delete networkid $network"
	}
	$result.msg = "removed $network"
	$result.changed = $true
}
# if state -eq present
# create or modify the subnet
else
{
	# check if the subnet exists
	$exists = $false
	try
	{
		$ipamSubnet = Get-IpamSubnet -NetworkId $network
		$exists = $true
	}
	catch [System.Management.Automation.RuntimeException]
	{
		$exists = $false
	}
	#if it exists, modify the properties
	if($exists)
	{
		try
		{	
			if($vlan)
			{
				Set-IpamSubnet -NetworkId $network -VlanId $vlan
			}
			if($description)
			{
				Set-IpamSubnet -NetworkId $network -Description $description 
			}
			if($customConfiguration)
			{
				Set-IpamSubnet -NetworkId $network -AddCustomConfiguration "$customConfiguration"
			}
			if($owner)
			{
				Set-IpamSubnet -NetworkId $network -Owner $owner
			}
			if($networkType)
			{
				Set-IpamSubnet -NetworkId $network --NewNetworkType $networkType
			}
			if($addressSpace)
			{
				Set-IpamSubnet -NetworkId $network -NewAddressSpace $addressSpace
			}
		}
		catch [System.Management.Automation.RuntimeException]
		{
			$exists = $false
		}
		
		$resultList = @()
		$subnet = Get-IpamSubnet -NetworkId $network
		$sub = Set-QueryResults -subnet $subnet
		$result.changed = $true
		$resultList += $sub
		$result.subnets = $resultList
		$result.msg = "modified $network"
		Exit-Json -obj $result
	}
	# if it doesn't exist, try to add it
	else
	{
		try
		{
			Add-IpamSubnet -Name $subnetName -NetworkId $network
		}
		catch [System.Management.Automation.RuntimeException]
		{
			Fail-Json $result  "unable to add $subnetName with networkid $network"
		}
		
		if($vlan)
		{
			Set-IpamSubnet -NetworkId $network -VlanId $vlan
		}
		if($description)
		{
			Set-IpamSubnet -NetworkId $network -Description $description 
		}
		if($customConfiguration)
		{
			Set-IpamSubnet -NetworkId $network -AddCustomConfiguration "$customConfiguration"
		}
		if($owner)
		{
			Set-IpamSubnet -NetworkId $network -Owner $owner
		}
		if($networkType)
		{
			Set-IpamSubnet -NetworkId $network -NewNetworkType $networkType
		}
		if($addressSpace)
		{
			Set-IpamSubnet -NetworkId $network -NewAddressSpace $addressSpace
		}
		$resultList = @()
		$subnet = Get-IpamSubnet -NetworkId $network
		$sub = Set-QueryResults -subnet $subnet
		$result.changed = $true
		$resultList += $sub
		$result.subnets = $resultList
		$result.msg = "created $network"
		Exit-Json -obj $result
	}
}

# result objects

Exit-Json -obj $result