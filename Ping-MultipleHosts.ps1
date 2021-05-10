<#PSScriptInfo
.VERSION 1.0

.GUID d6bb6029-c707-4814-a82e-e5cf06e7b404

.AUTHOR Dylan Hicks

.COPYRIGHT Copyright (c) 2021 Dylan Hicks

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

.TAGS Network Ping ICMP Diagnostics Troubleshooting

.LICENSEURI https://github.com/dylanh333/TechieTools/blob/master/LICENSE

.PROJECTURI https://github.com/dylanh333/TechieTools

.RELEASENOTES
1.0 Initial release.
#>

<#
.SYNOPSIS
 Pings multiple hosts simultaneously via ICMP, and outputs their resulting round-trip times (RTT) in tabular form.

.DESCRIPTION 
 Pings multiple hosts simultaneously via ICMP, and outputs their resulting round-trip times (RTT) in tabular form.
By default, each row of output is an object with the timestamp and a column (property) most recent RTT for each host being pinged. Additional properties such as minimum, maximum, and average RTTs can be enabled as detailed below.

.PARAMETER Hosts
 An array of hostnames or IP addresses to ping.
Each hostname or address is used to name the properties of the resulting rows that this script outputs. Eg. if you ping "google.com", then the resulting output will have a property named Timestamp, and another named "google.com" with the last recorded round trip time from pinging "google.com".

.PARAMETER Count
 By default, each host is pinged continuously until execution is interrupted by pressing Ctrl-C.
If a Count is specified, then then the script will stop executing after outputting this many rows, which will usually result in each host being pinged this many times.
Some hosts may actually have their RTT sampled fewer times than the number of rows output, however, eg. if the specified Timeout is greater than the sample Interval, and a host has an RTT longer than the interval.

.PARAMETER Timeout
 The amount of time to wait - in milliseconds - for a host to respond with an ICMP echo reply, before treating it as timed out.
In the resulting output, the host's RTT value will be listed as the specified numeric timeout, and this value will also be used in the RTT column to signify any other transient errors that may arise when pinging this host, eg. a "Destination host unreachable" will result in the host's most recent RTT being logged as 1000, if the Timeout is set to 1000 ms.

.PARAMETER Interval
 How frequently to output host's RTT, in milliseconds.
Some hosts may have their RTT sampled less frequently, if their RTT itself is greater than the sample Interval, however a new row will be output every Internal with the most recently captured samples every Interval, and any hosts who have responded will have a new ICMP request sent off to be captured in the next interval.

.PARAMETER PayloadSize
 Allows the amount - in bytes - of junk data to be sent within the ICMP packet to be adjusted.
Useful in conjunction with DoNotFragment to test MTU.

.PARAMETER Ttl
 Sets the TTL field of the ICMP packet to the specified amount.
The TTL (Time To Live) limits the number of router hops the packet may traverse before it expires in transit.
Each time the ICMP packet passes through a router, the TTL is decremented, and if it reaches 0, the router itself replies with a TTl expired message.

.PARAMETER DoNotFragment
 Sets the ICMP "do not fragment" flag, preventing the ICMP packet being split into multiple packets if its size exceeds the MTU of the media it is traversing.

.PARAMETER OutputAll
 Outputs all additional columns (properties) that are normally hidden by default.
See the parameters that follow for a list of these properties and what they're for.

.PARAMETER OutputTimeout
 Includes an extra column after the "Timestamp" named "Timeout", which prints the configured timeout for every row of output.
This may be useful if you're graphing the output of this script, and wish to have an "upper bound".

.PARAMETER OutputMinMaxAvg
 For each listed host, also output additional columns with the minimum (Min), maximum (Max), and average (Avg) RTTs sampled for that host.
If a host is named "bing.com", then its main RTT column will also be named "bing.com", and its minimum, maximum, and average columns will be named "bing.com (Min)", "bing.com (Max)", and "bing.com (Avg)", respectively.

.PARAMETER OutputTxRx
 For each listed host, also output additional columns with the total number of ICMP requests sent (Tx) and received (Tx).
Like the previous parameter, if the hostname is "duckduckgo.com" the additional columns are named like "duckduckgo.com (Tx)".

.PARAMETER OutputLoss
 For each listed host, also output an additional column with the percentage of packets lost.
If a given host is named "host.com", then this corresonding column will be named "host.com (Loss %)"

.PARAMETER OutputStatus
 For each listed host, also output an additional column listing the last status, eg. "Success", "TimedOut", and any other IP status names defined in the .NET enum System.Net.NetworkInformation.IPStatus.
Any other errors that are encountered but not covered by this enum are output as "Unknown", and a warning is instead printed to the console with further details.
If the host's name is "host.com", then the resulting column for this is named "host.com (Status)"

.EXAMPLE
 ./Ping-MultipleHosts.ps1 -Hosts 'google.com','10.0.0.1','192.168.0.1' -Timeout 500 -Count 5 | Format-Table
 # Pings the above hosts with a timeout of 500 ms, and only outputs 5 rows before exiting

.EXAMPLE
 ./Ping-MultipleHosts.ps1 -Hosts 'google.com','10.0.0.1','192.168.0.1' -OutputLoss | Format-List
 # Includes the percentage packet loss for each host above in the ping results

.EXAMPLE
 ./Ping-MultipleHosts.ps1 -Hosts 'google.com','10.0.0.1','192.168.0.1' | ForEach-Object {$_ | Format-Table}
 # Outputs as a table, with the table headers displayed for every row

.EXAMPLE
 ./Ping-MultipleHosts.ps1 -Hosts 'google.com','10.0.0.1','192.168.0.1' -OutputAll | Export-Csv -NoTypeInformation 'ping.csv'
 # Includes all additional columns described above, and saves the resulting ping times to a CSV

#> 

[CmdletBinding()]
Param (
    [Parameter(Mandatory=$true)]
    [String[]] $Hosts,
    
    [uint32] $Count = 0,
    [uint32] $Timeout = 1000,
    [uint32] $Interval = 1000,

    [uint16] $PayloadSize = 0,
    [byte] $Ttl = 30,
    [Switch] $DoNotFragment,

    [Switch] $OutputAll,
    [Switch] $OutputTimeout = $OutputAll,
    [Switch] $OutputMinMaxAvg = $OutputAll,
    [Switch] $OutputTxRx = $OutputAll,
    [Switch] $OutputLoss = $OutputAll,
    [Switch] $OutputStatus = $OutputAll
)

$ErrorActionPreference = 'Stop'

try {
    # Ping-sender agents, pre-resolved host addresses, and running ping tasks for each host
    $Pings = New-Object System.Net.NetworkInformation.Ping[] $Hosts.Length
    $Addrs = New-Object System.Net.IPAddress[] $Hosts.Length
    $Tasks = New-Object System.Threading.Tasks.Task[System.Net.NetworkInformation.PingReply][] $Hosts.Length

    # Statistics for each host
    $TotTx = New-Object uint64[] $Hosts.Length
    $TotRx = New-Object uint64[] $Hosts.Length
    $Times = New-Object uint32[] $Hosts.Length
    $MinTi = New-Object uint32[] $Hosts.Length
    $MaxTi = New-Object uint32[] $Hosts.Length
    $AvgTi = New-Object single[] $Hosts.Length
    $Status = New-Object System.Net.NetworkInformation.IPStatus[] $Hosts.Length

    # Allocate Payload to send for when a custom payload size is specified, along with settings for ping
    $Payload = New-Object byte[] $PayloadSize # Can be empty
    $Options = New-Object System.Net.NetworkInformation.PingOptions $Ttl,$DoNotFragment

    # Ping continously if $Count -eq 0, or otherwise until $Count is reached
    # If continuously, $c will still get incremented to 1 to indicate that all pings have
    # completed at least once.
    for([uint32] $c = 0; $Count -eq 0 -or $c -le $Count; ($Count -eq 0 -and $c -eq 1) -or $c++){
        $Output = New-Object -TypeName PSObject -Property @{Timestamp = Get-Date}
        
        # Add Timeout field, if OutputTimeout is enabled - useful as an upper bound for graphing
        if($OutputTimeout){
            $Output | Add-Member -MemberType NoteProperty -Name 'Timeout' -Value $Timeout
        }

        for($i = 0; $i -lt $Hosts.Length; $i++){
            # Initialise array entries for each host, if they haven't been
            if(-not $Pings[$i]){
                $Pings[$i] = New-Object System.Net.NetworkInformation.Ping

                try {
                    $Addrs[$i] = [System.Net.Dns]::GetHostAddresses($Hosts[$i])[0]
                }
                catch {
                    throw ('Error resolving "{0}" to IP address: {1}' -f $Hosts[$i],$Error[0].Exception.InnerException.Message)
                }

                $Times[$i] = $TotRx[$i] = $TotTx[$i] = $MaxTi[$i] = $AvgTi[$i] = 0
                $MinTi[$i] = [uint32]::MaxValue
            }

            # Check for any hosts whose pings have completed, and update their statistics accordingly 
            if($Tasks[$i].IsCompleted){
                # Only update TotTx *after* a given ping completes, that way we can
                # easily use this count to suppress output until all pings have
                # completed at least one iteration.
                # (a timeout or error still counts as "completed")
                $TotTx[$i]++
                
                # Successfuly received a reply within the Timeout, so update stats
                if($Tasks[$i].Result -and $Tasks[$i].Result.Status -eq 0){
                    $TotRx[$i]++
                    $Times[$i] = $Tasks[$i].Result.RoundtripTime
                    $Status[$i] = $Tasks[$i].Result.Status

                    if($OutputMinMaxAvg){
                        $MinTi[$i] = [Math]::Min($Times[$i], $MinTi[$i])
                        $MaxTi[$i] = [Math]::Max($Times[$i], $MaxTi[$i])
                        $AvgTi[$i] = (($TotRx[$i]-1)/$TotRx[$i])*$AvgTi[$i] + (1/$TotRx[$i])*$Times[$i]
                    }
                }

                # Timeout reached or error occurred
                else {
                    $Times[$i] = $Timeout # Use a RTT of Timeout to indicate an error or lack of reply
                    
                    if($Tasks[$i].Result){
                        $Status[$i] = $Tasks[$i].Result.Status
                    }
                    elseif($Tasks[$i].Exception){
                        $Status[$i] = [System.Net.NetworkInformation.IPStatus]::Unknown
                        Write-Warning ('Ping to {0} failed with exception: {1}' -f $Hosts[$i],$Tasks[$i].Exception.Message)
                    }
                    else {
                        $Status[$i] = [System.Net.NetworkInformation.IPStatus]::Unknown
                        Write-Warning ('Ping to {0} failed for an unknown reason.' -f $Hosts[$i])
                    }
                }

                $Tasks[$i] = $null
            }

            # Start a new ping for any hosts that don't have one currently running
            if($null -eq $Tasks[$i]){
                $Tasks[$i] = $Pings[$i].SendPingAsync($Addrs[$i], $Timeout, $Payload, $Options)
            }

            # Reset $c to 0 if any hosts still have a $TotTx of 0
            # This means that they still haven't completed their first ping
            if($TotTx[$i] -eq 0){
                $c = 0
            }
            # Otherwise, add the selected staticstics for this host to the Output
            else {
                $Output | Add-Member -MemberType NoteProperty -Name $Hosts[$i] -Value $Times[$i]

                if($OutputMinMaxAvg){
                    $Output | Add-Member -MemberType NoteProperty -Name "$($Hosts[$i]) (Min)" -Value $MinTi[$i]
                    $Output | Add-Member -MemberType NoteProperty -Name "$($Hosts[$i]) (Max)" -Value $MaxTi[$i]
                    $Output | Add-Member -MemberType NoteProperty -Name "$($Hosts[$i]) (Avg)" -Value $AvgTi[$i]
                }

                if($OutputTxRx){
                    $Output | Add-Member -MemberType NoteProperty -Name "$($Hosts[$i]) (Tx)" -Value $TotTx[$i]
                    $Output | Add-Member -MemberType NoteProperty -Name "$($Hosts[$i]) (Rx)" -Value $TotRx[$i]
                }

                if($OutputLoss){
                    $Output | Add-Member -MemberType NoteProperty -Name "$($Hosts[$i]) (Loss %)" -Value ([single](100 - 100 * $TotRx[$i]/$TotTx[$i]))
                }

                if($OutputStatus){
                    $Output | Add-Member -MemberType NoteProperty -Name "$($Hosts[$i]) (Status)" -Value $Status[$i]
                }
            }
        }

        # Yield Output to the pipeline,
        # but only if all hosts have completed at their first ping.
        if($c -gt 0){
            $Output
        }

        Start-Sleep -Milliseconds $Interval
    }
}

catch {
    throw $Error[0]
}

# Code in the finally block *should* still execute even if Ctrl-C is pressed, that way we can clean up before
# returning to the current PowerShell session, otherwise memory we've used can still remain beyond the lifetime
# of the script
finally {
    # The documentation says we must manually Dispose() of Ping objects when we're done with them
    $Pings | where {$_} | %{$_.Dispose()}
}