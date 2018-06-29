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
$state = Get-AnsibleParam -obj $params -name "state" -type "str" -default "present" -validateset "absent","present","query"
#
$context = Get-AnsibleParam -obj $params -name "context" -type "str"
$site = Get-AnsibleParam -obj $params -name "site" -type "str"
$subnetName = Get-AnsibleParam -obj $params -name "subnetName" -type "str"
$network = Get-AnsibleParam -obj $params -name "network" -type "str"

$result = @{
    changed = $false
}

# code goes here
# if state is query, check if the subnet exists in IPAM
if($state -eq "query")
{
	$resultList = @()
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
	
	foreach ($subnet in $Subnets)
	{
		$s = @{}
		$s.name = $subnet.Name
		$s.context = ""
		$s.site = ""
		$s.city = ""
		$s.networkID = $subnet.NetworkId
		$customConfig = $subnet.CustomConfiguration -split ";"

		foreach ($line in $customConfig)
			{
				if ($line -like "Context*")
				{
					$s.context = ($line -split "=")[1]
				}
				if ($line -like "Site*")
				{
					$s.site = ($line -split "=")[1]
				}
				if ($line -like "City*")
				{
					$s.city = ($line -split "=")[1]
				}
			}
		$resultList += $s
	}
	$result.changed = $true
	$result.subnets = $resultList
	
}
# If state is present, return a list of the subnets
elseif($state -eq "present")
{
	$resultList = @()
	if($context -and $site)
	{
		#get public subnets
		if ($addressCategory -eq "public")
		{
			try
			{
				$Subnets = Get-IpamSubnet -AddressFamily $addressFamily | where {$_.CustomConfiguration -Like "*Context=$context;Site=$site*"} | where-object {$_.Owner -eq "DE"}
			}
			
			catch [System.Management.Automation.RuntimeException]
			{
				$result.msg = "Unable to find public $addressFamily subnets by site $site and context $context"
				Exit-Json -obj $result
			}
		}
		# get private subnets
		elseif ($addressCategory -eq "private")
		{
			try
			{
				$Subnets = Get-IpamSubnet -AddressFamily $addressFamily | where {$_.CustomConfiguration -Like "*Context=$context;Site=$site*"} | where-object {$_.Owner -ne "DE"}
			}
			
			catch [System.Management.Automation.RuntimeException]
			{
				$result.msg = "Unable to find private $addressFamily subnets by site $site and context $context"
				Exit-Json -obj $result
			}
		}
		# get all the subnets
		else
		{
			try
			{
				$Subnets = Get-IpamSubnet -AddressFamily $addressFamily | where {$_.CustomConfiguration -Like "*Context=$context;Site=$site*"}
			}
			
			catch [System.Management.Automation.RuntimeException]
			{
				$result.msg = "Unable to find $addressFamily subnets by site $site and context $context"
				Exit-Json -obj $result
			}
		}
		# fill in the results
		foreach ($subnet in $Subnets)
		{
			$s = @{}
			$s.name = $subnet.Name
			$s.context = ""
			$s.site = ""
			$s.city = ""
			$s.networkID = $subnet.NetworkId
			$customConfig = $subnet.CustomConfiguration -split ";"
	
			foreach ($line in $customConfig)
				{
					if ($line -like "Context*")
					{
						$s.context = ($line -split "=")[1]
					}
					if ($line -like "Site*")
					{
						$s.site = ($line -split "=")[1]
					}
					if ($line -like "City*")
					{
						$s.city = ($line -split "=")[1]
					}
				}
			$resultList += $s
		}
		$result.changed = $true
		$result.subnets = $resultList
	}
	else
	{
		$result.msg = "Nothing to search"
		Exit-Json -obj $result
	}
}
else
{
	Fail-Json $result "Invalid state"
}

# result objects

Exit-Json -obj $result