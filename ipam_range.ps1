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

 
# Gets and IPAM range and returns the needed variables
# Example: Set-Attr $result "changed" $true
Function Get-Range($start, $end)
{
	try
	{
		$Range = Get-IpamRange -StartIPAddress $start -EndIPAddress $end
	}
	catch [System.Management.Automation.RuntimeException]
	{
		$result.msg = "Unable to query range $startRange - $endRange"
		Exit-Json -obj $result
	}
	$result.subnet = $Range.NetworkID
	$result.rangeName = $Range.Description
	$result.size = $Range.AssignedAddresses
	$result.used = $Range.UtilizedAddresses
	$result.percentUtilized = $Range.PercentageUtilized
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
# 
$state = Get-AnsibleParam -obj $params -name "state" -type "str" -default "present" -validateset "absent","present","query","list"
#IPAM search variables
$startRange = Get-AnsibleParam -obj $params -name "startRange" -type "str"
$endRange = Get-AnsibleParam -obj $params -name "endRange" -type "str"
$subnet = Get-AnsibleParam -obj $params -name "subnet" -type "str"
$size = Get-AnsibleParam -obj $params -name "size" -type "int"
$name = Get-AnsibleParam -obj $params -name "name" -type "str"
$removeIP = Get-AnsibleParam -obj $params -name "removeIP" -type "bool" -default $false
$rangeName = Get-AnsibleParam -obj $params -name "rangeName" -type "str"
#
$result = @{
    changed = $false
}

# if state is query, check if the range exists in IPAM.
# returns the range if a provided IP
if($state -eq "query")
{
	if($startRange -and $endRange)
	{
		Get-Range -start $startRange -end $endRange
	}
	elseif($rangeName)
	{
		try
		{
			$Range = get-ipamrange -AddressFamily IPv4 | Where-Object -FilterScript {$_.Description -eq $rangeName}
		}
		catch [System.Management.Automation.RuntimeException]
		{
			$result.msg = "Unable to find range $rangeName"
			Exit-Json -obj $result
		}
		$result.subnet = $Range.NetworkID
		$result.rangeName = $Range.Description
		$result.size = $Range.AssignedAddresses
		$result.used = $Range.UtilizedAddresses
		$result.percentUtilized = $Range.PercentageUtilized
	}
	else
	{
		$result.msg = "No query parameter.  Enter ip or range name"
		Exit-Json -obj $result
	}
	$result.startRange = $startRange
	$result.endRange = $endRange
}
# If state is present assign a free range
elseif($state -eq "present")
{
	if($size -and $subnet -and $name)
	{
		try
		{
			$ipamSubnet = Get-IpamSubnet -NetworkId $subnet
		}
		catch
		{
			$result.msg = "Unable to find subnet $subnet"
			Exit-Json -obj $result
		}
		$ipamRange = Find-IpamFreeRange -InputObject $ipamSubnet -NumberOfAddresses $size
		$startRange = $ipamRange.StartIPAddress.IPAddressToString
		$endRange = $ipamRange.EndIPAddress.IPAddressToString
		$networkID = $ipamRange.NetworkID
		$range = Add-IpamRange -NetworkId $networkID -StartIPAddress $startRange -EndIPAddress $endRange -description $name
		# call the function to get the custom configuration
		Get-Range -start $startRange -end $endRange
	}
	else
	{
		Fail-Json $result "Missing parameter(s) to get free range"
	}
	$result.startRange = $startRange
	$result.endRange = $endRange
}
elseif($state -eq "list")
{
	if($subnet)
	{
		try
		{
			$ipamSubnet = Get-IpamSubnet -NetworkId $subnet
		}
		catch
		{
			$result.msg = "Unable to find subnet $subnet"
			Exit-Json -obj $result
		}
		$ipamRanges = Get-IpamRange -MappingToSubnet $ipamSubnet
		$subnetRanges =  @{
			networkID = $ipamSubnet.NetworkId
			subnetName = $ipamSubnet.Name
			ranges = @()
		}
		foreach ($r in $ipamRanges)
		{
			$subnetRanges.ranges += @{
			name = $r.Description
			start = $r.StartIPAddress
			end = $r.EndIPAddress
			percentUtilized = $r.PercentageUtilized
			numberUtilized = $r.UtilizedAddresses
			numberAvailable = ($r.AssignedAddresses - $r.UtilizedAddresses)}
		}
	}
	else
	{
		Fail-Json $result "Missing parameter(s) to get free range"
	}
	$result.subnet = $subnetRanges
}
# if state is absent, remove the range.  If $removeIP is set, it will also delete the associated IP addresses
elseif($state -eq "absent")
{
	if($startRange -and $endRange -and $removeIP)
	{
		try
		{
			Get-IpamRange -StartIPAddress $startRange -EndIPAddress $endRange|Remove-IpamRange -DeleteMappedAddresses -Force
		}
		catch
		{
			$result.msg = "Unable to delete $startRange - $endRange and IPs"
			Exit-Json -obj $result
		}
	}
	elseif($startRange -and $endRange)
	{
		try
		{
			Get-IpamRange -StartIPAddress $startRange -EndIPAddress $endRange|Remove-IpamRange -Force
		}
		catch
		{
			$result.msg = "Unable to delete $startRange - $endRange"
			Exit-Json -obj $result
		}
	}
	else
	{
		Fail-Json $result "Missing parameter(s) to delete range"
	}
	$result.startRange = $startRange
	$result.endRange = $endRange
}
else
{
	Fail-Json $result "Invalid state"
}

# result objects
$result.changed = $true
$result.state = $state


Exit-Json -obj $result