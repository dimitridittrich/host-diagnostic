<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2017 v5.4.145
	 Created on:   	12/08/2019 02:23 
	 Created by:   	Dimitri Dittrich
	 Organization: Dimitri's Company
	 Filename:    	
	===========================================================================
	.DESCRIPTION
		Aplicação destinada a facilitar os diagnósticos da equipe de TI.
#>

function Get-ScriptDirectory
{
	[OutputType([string])]
	param ()
	if ($null -ne $hostinvocation)
	{
		Split-Path $hostinvocation.MyCommand.path
	}
	else
	{
		Split-Path $script:MyInvocation.MyCommand.Path
	}
}
$scriptPath = Get-ScriptDirectory

Remove-Item $scriptPath\HostDiagnostic -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType directory -Path $scriptPath\HostDiagnostic -Force -ErrorAction SilentlyContinue | Out-Null

cls
#------------IMPORT-MODULES-------------
#try
#{
#	Import-Module \\nomedaempresa.local\netlogon\powershell\NomeDaEmpresa.psm1 -ErrorAction Stop
#	Import-Module \\nomedaempresa.local\netlogon\powershell\VeryMuchFunctions.psm1 -ErrorAction Stop
#}
#catch [System.IO.FileNotFoundException]
#{
#	Write-Error "Não foi possível carregar módulo auxiliar: $($_.Exception.Message)"
#}
#---------------------------------------
$i = 1

[array]$diagnostics = @()

$nics = (Get-NetAdapterHardwareInfo).Name
$niccount = 1
foreach ($linha in $nics)
{
	$diagsobj = New-Object PSObject -Property @{ "InterfaceName" = ""; "InterfaceDescription" = ""; "MediaConnectionState" = ""; "MacAddress" = ""; "LinkSpeed" = ""; "IpAddress" = ""; "PrefixLength" = ""; "IPv4DefaultGateway" = ""; "DNSServer" = "" }
	############################################START_INTERFACES_DETAILS############################################
	#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
	$i = $i + 5; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Iniciando Leitura das interfaces de rede..."; Start-Sleep 3
	
	Remove-Variable -Name "adapter$niccount" -Force -ErrorAction SilentlyContinue
	New-Variable -Name "adapter$niccount" -Value $linha
	$diagsobj.InterfaceName = (Get-Variable -Name "adapter$niccount" -ValueOnly)
	$diagsobj.InterfaceDescription = (Get-NetAdapter -Name $linha).InterfaceDescription
	$diagsobj.MediaConnectionState = (Get-NetAdapter -Name $linha).MediaConnectionState
	$diagsobj.MacAddress = (Get-NetAdapter -Name $linha).MacAddress
	$diagsobj.LinkSpeed = (Get-NetAdapter -Name $linha).LinkSpeed
	$diagsobj.IpAddress = (Get-NetIPAddress -InterfaceAlias $linha).IpAddress
	$diagsobj.PrefixLength = "/"+((Get-NetIPAddress -InterfaceAlias $linha).PrefixLength)
	$diagsobj.IPv4DefaultGateway = ((Get-NetIPConfiguration -InterfaceAlias $linha).IPv4DefaultGateway).NextHop
	$diagsobj.DNSServer = [string]((Get-NetIPConfiguration -InterfaceAlias $linha).DNSServer).ServerAddresses -creplace " ", ","
	#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
	$i = $i + 5; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Exportando informações das interfaces de rede..."; Start-Sleep 3
	$diagnostics += $diagsobj
	############################################END_INTERFACES_DETAILS############################################
}

$diagnostics | select InterfaceName, InterfaceDescription, MediaConnectionState, MacAddress, LinkSpeed, IpAddress, PrefixLength, IPv4DefaultGateway, DNSServer | Export-Csv $scriptPath\HostDiagnostic\NetworkInterfaces.csv -Encoding UTF8 -NoTypeInformation -Delimiter ";"





############################################START_PROXY_SETTINGS############################################
#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
$i = $i + 5; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Coletando informações das configurações de proxy..."; Start-Sleep 3
Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | select ProxyEnable, ProxyServer, ProxyOverride | Export-Csv $scriptPath\HostDiagnostic\ProxySettings.csv -Delimiter ";" -Encoding UTF8 -NoTypeInformation
#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
$i = $i + 5; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Exportando informações das configurações de proxy..."; Start-Sleep 3
############################################END_PROXY_SETTINGS############################################

############################################START_SYSTEMINFO############################################
#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
$i = $i + 5; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Coletando informações gerais do sistema (SystemInfo)..."; Start-Sleep 3
systeminfo /fo csv > $scriptPath\HostDiagnostic\SYSTEMINFO.csv
$systeminfo = Import-Csv $scriptPath\HostDiagnostic\SYSTEMINFO.csv -Delimiter ","
$systeminfo | Export-Csv $scriptPath\HostDiagnostic\SYSTEMINFO.csv -Delimiter ";" -Encoding UTF8 -NoTypeInformation
#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
$i = $i + 5; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Exportando informações gerais do sistema (SystemInfo)..."; Start-Sleep 3
############################################END_SYSTEMINFO############################################




############################################START_FUNCTION_TRACE-ROUTE############################################
#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
$i = $i + 5; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Gerando Function Trace-Route..."; Start-Sleep 3
function Trace-Route
{
	[CmdletBinding()]
	param (
		[int]$Timeout = 1000
		 ,
		[Parameter(Mandatory = $true)]
		[string]$TargetHost
		 ,
		[int]$StartingTtl = 1
		 ,
		[int]$EndingTtl = 128
		 ,
		[switch]$ResolveDns
	)
	
	# Create Ping and PingOptions objects
	$Ping = New-Object -TypeName System.Net.NetworkInformation.Ping;
	$PingOptions = New-Object -TypeName System.Net.NetworkInformation.PingOptions;
	#Write-Debug -Message ('Created Ping and PingOptions instances');
	
	# Assign initial Time-to-Live (TTL) to the PingOptions instance
	$PingOptions.Ttl = $StartingTtl;
	
	# Assign starting TTL to the 
	$Ttl = $StartingTtl;
	
	# Assign a random array of bytes as data to send in the datagram's buffer
	$DataBuffer = [byte[]][char[]]'aa';
	
	# Loop from StartingTtl to EndingTtl
	while ($Ttl -le $EndingTtl)
	{
		
		# Set the TTL to the current
		$PingOptions.Ttl = $Ttl;
		
		# Ping the target host using this Send() override: http://msdn.microsoft.com/en-us/library/ms144956.aspx
		$PingReply = $Ping.Send($TargetHost, $Timeout, $DataBuffer, $PingOptions);
		
		# Get results of trace
		$TraceHop = New-Object -TypeName PSObject -Property @{
			TTL		     = $PingOptions.Ttl;
			Status	     = $PingReply.Status;
			Address	     = $PingReply.Address;
			RoundTripTime = $PingReply.RoundtripTime;
			HostName	 = '';
		};
		
		# If DNS resolution is enabled, and $TraceHop.Address is not null, then resolve DNS
		# TraceHop.Address can be $null if 
		if ($ResolveDns -and $TraceHop.Address)
		{
			#Write-Debug -Message ('Resolving host entry for address: {0}' -f $TraceHop.Address);
			try
			{
				# Resolve DNS and assign value to HostName property of $TraceHop instance
				$TraceHop.HostName = [System.Net.Dns]::GetHostEntry($TraceHop.Address).HostName;
			}
			catch
			{
				#Write-Debug -Message ('Failed to resolve host entry for address {0}' -f $TraceHop.Address);
				#Write-Debug -Message ('Exception: {0}' -f $_.Exception.InnerException.Message);
			}
		}
		
		# Once we get our first, succesful reply, we have hit the target host and 
		# can break out of the while loop.
		if ($PingReply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
		{
			#Write-Debug -Message ('Successfully pinged target host: {0}' -f $TargetHost);
			Write-Output -InputObject $TraceHop;
			break;
		}
		# If we get a TtlExpired status, then ping the device directly and get response time
		elseif ($PingReply.Status -eq [System.Net.NetworkInformation.IPStatus]::TtlExpired)
		{
			$PingReply = $Ping.Send($TraceHop.Address, $Timeout, $DataBuffer, $PingOptions);
			$TraceHop.RoundTripTime = $PingReply.RoundtripTime;
			
			Write-Output -InputObject $TraceHop;
		}
		else
		{
			# $PingReply | select *;
		}
		
		# Increment the Time-to-Live (TTL) by one (1) 
		$Ttl++;
		#Write-Debug -Message ('Incremented TTL to {0}' -f $Ttl);
	}
}
############################################END_FUNCTION_TRACE-ROUTE############################################

############################################START_NETWORK-TESTS############################################
#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
$i = $i + 5; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Iniciando testes de rede..."; Start-Sleep 3
[array]$teste = "===============Teste PING GOOGLE==============="
$teste += Test-Connection 8.8.8.8 -TimeToLive 63 -Count 10
$teste += "=============================================="
$teste += ""
$teste += "===============Teste TRACE ROUTE GOOGLE==============="
$teste += Test-NetConnection 8.8.8.8 -TraceRoute | Select-Object PingSucceeded, SourceAddress, RemoteAddress
$teste += Trace-Route -TargetHost 8.8.8.8 -ResolveDns
$teste += "=============================================="
$teste += ""
$teste += "===============Teste DNS GOOGLE==============="
$teste += (nslookup google.com.br) 2>$null
$teste += "=============================================="
$teste += ""
$teste += "===============Teste PING Portal NomeDaEmpresa==============="
$teste += Test-Connection 189.35.6.173 -TimeToLive 63 -Count 10
$teste += "=============================================="
$teste += ""
$teste += "===============Teste TRACE ROUTE Portal NomeDaEmpresa==============="
$teste += Test-NetConnection 189.35.6.173 -TraceRoute | Select-Object PingSucceeded, SourceAddress, RemoteAddress
$teste += Trace-Route -TargetHost 189.35.6.173 -ResolveDns
$teste += "=============================================="
$teste += ""
$teste += "===============Teste DNS Portal NomeDaEmpresa==============="
$teste += (nslookup portal.NomeDaEmpresa.com.br) 2>$null
$teste += "=============================================="
$teste >> $scriptPath\HostDiagnostic\networktests.txt
#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
$i = $i + 5; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Exportando testes de rede..."; Start-Sleep 3
############################################END_NETWORK-TESTS############################################

############################################START_GPRESULT############################################
#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
$i = $i + 5; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Gerando GPRESULT no contexto de User e Computer..."; Start-Sleep 3
gpresult -h $scriptPath\HostDiagnostic\GPResultUser.html /scope:user
gpresult -h $scriptPath\HostDiagnostic\GPResultComputer.html /scope:computer
#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
$i = $i + 5; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Exportando GPRESULT no contexto de User e Computer..."; Start-Sleep 3
#############################################END_GPRESULT############################################












#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
$i = 98; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Comprimindo pasta HostDiagnostic..."; Start-Sleep 3
Compress-Archive "$scriptPath\HostDiagnostic\" -DestinationPath "$scriptPath\HostDiagnostic\HostDiagnostic.zip"

#@@@@@@@@@@@@@@@@@@@@@@@@PROGRESS@@@@@@@@@@@@@@@@@@@@@@@@#
$i = 100; Write-Progress -Activity "HostDiagnostic" -PercentComplete $i -Status "Coleta finalizada!"; Start-Sleep 5


#get-netadapter | where { $_.Name -like '*Wi-Fi*' -or $_.Name -like '*Ethernet*' -or $_.Name -like '*Wifi*' }


# SIG # Begin signature block
# MIIEOgYJKoZIhvcNAQcCoIIEKzCCBCcCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUS8meQYrIBtlf4jqMVRf+CQe5
# WK6gggJEMIICQDCCAa2gAwIBAgIQVB3qufqZrZpKhWR9rnNo7zAJBgUrDgMCHQUA
# MCwxKjAoBgNVBAMTIVBvd2VyU2hlbGwgTG9jYWwgQ2VydGlmaWNhdGUgUm9vdDAe
# Fw0xNzA3MTQxMjEyMTdaFw0zOTEyMzEyMzU5NTlaMCExHzAdBgNVBAMTFkRpbWl0
# cmkgUG93ZXJTaGVsbCBDU0MwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALXt
# 21SuIH+ODd1F82+fp45oUFGw2R+NzvdfKyao44xABoxtqkv2uquqRbo1Fi+jsd80
# HzcHO3BOPUZJsFtuADZhQZmhV3oMjWoSaGmWgOaERkYb01AJo311LNMd9duwQjqz
# XY6VtOj4SnqwB9xY6VmUVvpsNdIPBsD9pziX3sdFAgMBAAGjdjB0MBMGA1UdJQQM
# MAoGCCsGAQUFBwMDMF0GA1UdAQRWMFSAEGPPo05+xF03EpNY4Co5jEqhLjAsMSow
# KAYDVQQDEyFQb3dlclNoZWxsIExvY2FsIENlcnRpZmljYXRlIFJvb3SCEHt8lZC+
# seeASfvlb8W6Jc4wCQYFKw4DAh0FAAOBgQApVBuK8PfCTBdPMTgv+o/sq0rVCc9Z
# ozaUkfUW91B8APzCL52cHmLN8GQsnm7Up2l0iD9ul3EqaAPrLaoxoeYdCrea5Boi
# TA+zYaS4Cp2oDL/SWtQH4TNpEbQEl+4a5Rn7iq8RqsB1m7EsG80Q1aDrzVyeLhYK
# 8IT6eqWnoiqR6TGCAWAwggFcAgEBMEAwLDEqMCgGA1UEAxMhUG93ZXJTaGVsbCBM
# b2NhbCBDZXJ0aWZpY2F0ZSBSb290AhBUHeq5+pmtmkqFZH2uc2jvMAkGBSsOAwIa
# BQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgor
# BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3
# DQEJBDEWBBRi5320gIsswsGX+gwUTl1cFbyRIjANBgkqhkiG9w0BAQEFAASBgDVD
# fwfRoFBlUPCagkatg/UTihTDXVM2fE8MHMvVWvT80Yx5YNL1gPhBWcoxLuqDWRBb
# iAvs40Nejmy02JqXVUbwfUKc00XRM6bGmEDmnBNwYjlCa1wKZPPg4aWW3Oj7fpf4
# R0PUPBJX3NrvQfW1qlG2hVgYAX54LC46z4IEAbsn
# SIG # End signature block
