param(
    [Parameter(Mandatory=$true)]
    [ValidateRange(1,90)]
    [int]
    $days,
    [Parameter(Mandatory=$true)]
    [string]
    $storageAccountName,
    [Parameter(Mandatory=$true)]
    [string]
    $storageContainer,
    [boolean]
    $eventHub = $false,
    [boolean]
    $azureMonitor = $false
)

function Get-AdalToken
{
    param(
    [Parameter(Mandatory=$true)]
    [string]
    $resource
    )

    # Add the ADAL Module
    Add-Type -Path "C:\Modules\User\Microsoft.IdentityModel.Clients.ActiveDirectory\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"

    # Get the connection information and certificate
    $connection = Get-AutomationConnection -Name 'AzureRunAsConnection'
    $clientCert = Get-AutomationCertificate -Name 'AzureRunAsCertificate'
    $clientId = $connection.ApplicationId
    $tenantId = $connection.TenantId

    # Create authentication context
    $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext("https://login.windows.net/$tenantId")
    
    # Create client credential
    $clientCredential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate("$clientId", $clientCert)

    # Acquire an access token
    $authResult = $authContext.AcquireTokenAsync($resource, $clientCredential)

    if (!$authResult.Result)
    {
        $errorMessage = "$($authResult.Exception)"
        throw $errorMessage
    }
    
    return $authResult.Result.AccessToken
}

function Get-AllManagementGroups
{
    param(
        [String]
        $mgmtGroupsApiVersion = '2018-03-01-preview',
        [Parameter(Mandatory=$true)]
        [string]
        $accessToken
    )

    # Form the request
    $tenantId = (Get-AzureRmContext).Tenant 
    $uri = "https://management.azure.com/providers/Microsoft.Management/managementGroups/$tenantId/descendants"
    $headers = @{ 'Authorization' = "Bearer $accessToken" }
    $method = 'GET'
    $body = @{ 'api-version' =  $mgmtGroupsApiVersion }
    $contentType = 'application/json'
    $mgmtGroupsList = @()

    # Issue the request to the REST API
    $mgmtGroupsChildren = Invoke-RestMethod -Uri $uri -Headers $headers -Method $method -Body $body -ContentType $contentType

    # Create a list with all the Management Group Names
    foreach ($child in $mgmtGroupsChildren.value)
    {
        if ($child.type -eq "/providers/Microsoft.Management/managementGroups")
        {
                $mgmtGroupsList += $child.name
        }
    }
    
    # Add the tenant root group management group to the list
    $mgmtGroupsList += $tenantId.Id

    return $mgmtGroupsList
}

function Get-ManagementGroupActivityLog
{
    param(
        [String]
        $mgmtGroupsApiVersion = '2017-03-01-preview',
        [Parameter(Mandatory=$true)]
        [string]
        $mgmtGroupId,
        [Parameter(Mandatory=$true)]
        [string]
        $accessToken,
        [Parameter(Mandatory=$true)]
        [int]
        $days
    )

    # Subtract one from max days to ensure limit of 90 days isn't reached
    $days = $days - 1

    # Initialize an empty array to store log entries
    $logEntries = @()

    # Create ISO 8601 timestamp subtracting the number of days specified for the user for use with the filter query paramater
    $dateFilterValue = (((Get-Date).AddDays(-($days)).ToString("yyyy-MM-ddT00:00:00Z")))

    # Form the request
    $tenantId = (Get-AzureRmContext).Tenant 
    $uri = "https://management.azure.com/providers/Microsoft.Management/managementGroups/$($mgmtGroupId)/providers/microsoft.insights/eventtypes/management/values"
    $headers = @{ 'Authorization' = "Bearer $accessToken" }
    $method = 'GET'
    $body = @{ 
        'api-version' =  $mgmtGroupsApiVersion
        '$filter' = "eventTimestamp ge '$dateFilterValue'"
    }
    $contentType = 'application/json'

    # Make the request to the REST API
    $results = Invoke-RestMethod -Uri $uri -Headers $headers -Method $method -Body $body -ContentType $contentType

    $logEntries += $results.value

    # Handle paged results
    while($results.NextLink)
    {
        $uri = $results.NextLink
        $results = Invoke-RestMethod -Uri $uri -Headers $headers -Method $method -ContentType $contentType
        $logEntries += $results.value
    }
    return $logEntries

}

function SendTo-Storage
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $storageAccountName,
        [Parameter(Mandatory=$true)]
        [string]
        $storageContainer,
        [Parameter(Mandatory=$true)]
        [string]
        $blobData,
        [Parameter(Mandatory=$true)]
        [string]
        $mgmtGroupName
    )

    # Get the current date and format it
    $todayDate = Get-Date -UFormat "%Y%m%d-%H%M"

    # Create a filename for the logs
    $logFile = "$todayDate-$mgmtGroupName.log"

    # Create a file object and store the log data in it
    $logItem = New-Item -ItemType File -Name $logFile
    $blobData | Out-File -FilePath $logFile -Append

    # Create the storage context and deliver it to Azure Storage
    $storageContext = New-AzureStorageContext -StorageAccountName $storageAccountName -UseConnectedAccount -Protocol "Https"
    $null = Set-AzureStorageBlobContent -File $logFile -Container $storageContainer -BlobType "Block" -Context $storageContext

}

function SendTo-Workspace
{
    param(
        [string]
        $logAnalyticsWorkspaceIdVar = 'logAnalyticsWorkspaceId',
        [string]
        $logAnalyticsWorkspaceKeyVar = 'logAnalyticsWorkspaceKey',  
        [Parameter(Mandatory=$true)]
        [string]
        $jsonData
    )

    # Create the function to create the authorization signature
    Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
    {
        $xHeaders = "x-ms-date:" + $date
        $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

        $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($sharedKey)

        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.Key = $keyBytes
        $calculatedHash = $sha256.ComputeHash($bytesToHash)
        $encodedHash = [Convert]::ToBase64String($calculatedHash)
        $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
        return $authorization
    }

    # Create the function to create and post the request
    Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
    {
        $method = "POST"
        $contentType = "application/json"
        $resource = "/api/logs"
        $rfc1123date = [DateTime]::UtcNow.ToString("r")
        $contentLength = $body.Length
        $signature = Build-Signature `
            -customerId $customerId `
            -sharedKey $sharedKey `
            -date $rfc1123date `
            -contentLength $contentLength `
            -method $method `
            -contentType $contentType `
            -resource $resource
        $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

        $headers = @{
            "Authorization" = $signature;
            "Log-Type" = $logType;
            "x-ms-date" = $rfc1123date;
            "time-generated-field" = $TimeStampField;
        }

        $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
        return $response.StatusCode
    }

    # Get Log Analytics Workspace Id and Key from encrypted variables
    $CustomerId = Get-AutomationVariable -Name  $logAnalyticsWorkspaceIdVar
    $SharedKey = Get-AutomationVariable -Name $logAnalyticsWorkspaceKeyVar

    # Specify the name of the record type that you'll be creating
    $LogType = "mgmtGroupActivityLogs"

    # You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
    $TimeStampField = "eventTimestamp"

    # Create an empty array and set the max log size to under 1MB so it doesn't exceed output max of Runbooks
    $maxLogSize = 200000
    $logData = ConvertFrom-Json $jsonData
    $logPackage = @()

    foreach ($logEntry in $logData)
    {
        if ($logPackage)
        {
            $logPackageSize = [System.Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $logPackage))
            $logEntrySize = [System.Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json $logEntry))

            if (($logPackageSize + $logEntrySize) -gt $maxLogSize)
            {
            # Submit the data to the API endpoint
                Write-Output "Sending chunk of results to avoid hitting max stream size..."
                $sendResults = Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $logPackage))) -logType $logType
                
                # Handle any throttling that may happen
                while ($sendResults -eq 429)
                {
                    Start-Sleep -Second 10
                    $sendResults = Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $logPackage))) -logType $logType
                }
                if ($sendResults -ne 200)
                {
                    $errorMessage = "Failed to send data to Azure Monitor API.  Status code was: $sendResults"
                    throw $errorMessage
                }
                $logPackage = @()
            }
            $logPackage = $logPackage + $logEntry
        }
        else
        {
            $logPackage = $logPackage + $logEntry
        }
    }
    Write-Output "Writing remaining data to Log Analytics.."
    $sendResults = Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $logPackage))) -logType $logType
    if ($sendResults -ne 200)
    {
        $errorMessage = "Failed to send data to Azure Monitor API.  Status code was: $sendResults"
        throw $errorMessage
    }
}

function SendTo-EventHub
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $jsonData
    )

    # Load necessary .NET modules for Event Hub
    Add-Type -Path "C:\Modules\User\System.Diagnostics.DiagnosticSource\System.Diagnostics.DiagnosticSource.dll"
    Add-Type -Path "C:\Modules\User\Microsoft.Azure.Amqp\Microsoft.Azure.Amqp.dll"
    Add-Type -Path "C:\Modules\User\Microsoft.Azure.EventHubs\Microsoft.Azure.EventHubs.dll"


    # Get connection string from variables
    $connectionString = Get-AutomationVariable -Name 'eventHubConnString'
    
    # Convert log data to a collection of PSObjects
    $logData = ConvertFrom-Json $jsonData

    # Create Event Hub Client
    $eventHubClient = [Microsoft.Azure.EventHubs.EventHubClient]::CreateFromConnectionString($connectionString)

    # Loop through the collection of log entries and write each to the Event Hub
    foreach ($logEntry in $logData)
    {

        # Create the event and send it
        $eventData =  ([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $logEntry)))
        $null = ($eventHubClient.SendAsync($eventData)).GetAwaiter().GetResult()
    }

    # Close out the client
    $eventHubClient.Close()
}

# Establish Azure content for use with child Runbooks
$Conn = Get-AutomationConnection -Name AzureRunAsConnection
$null = Connect-AzureRmAccount -ServicePrincipal -Tenant $Conn.TenantID -ApplicationId $Conn.ApplicationID -CertificateThumbprint $Conn.CertificateThumbprint

# Get an access token for the Azure Resource Management API
Write-Output "Getting an access token for the Azure Resource Management API..."
$accessToken = Get-AdalToken -resource "https://management.azure.com/"

# Get a listing of Management Group names
Write-Output "Getting a listing of Management Groups in the tenant..."
$mgmtGroups = Get-AllManagementGroups -accessToken $accessToken
    
# Iterate through each Management Group and get the Activity Logs
Write-Output "Begin getting the Activity Logs for the Management Groups..."
foreach ($mgmtGroup in $mgmtGroups)
{
    Write-Output "Processing the Activity Logs for the $mgmtGroup management group..."

    # Retrieve logs for the management group and convert the output to JSON
    $logs = Get-ManagementGroupActivityLog -days $days -accessToken $accessToken -mgmtGroupId $mgmtGroup

    if ($logs)
    {
        # Store the log data on Azure Storage as a blob
        $logsForStorage = $logs | ConvertTo-JSON
        Write-Output "Sending data to Azure Storage..."
        $null = SendTo-Storage -StorageAccountName $storageAccountName -StorageContainer $storageContainer -blobData $logsForStorage -mgmtGroupName $mgmtGroup
        Write-Output "Data successfully written to storage"

        # Send the logs to Azure Monitor
        if ($azureMonitor -eq $true)
        {
            Write-Output "Sending data to Azure Monitor..."
            SendTo-Workspace -jsonData $logsForStorage
            Write-Output "Data successfuly delivered to Azure Monitor"
        }


        # Send the logs to an Event Hub
        if ($eventHub -eq $true)
        {
            Write-Output "Sending data to Event Hub..."
            SendTo-EventHub -jsonData $logsForStorage
            Write-Output "Data successfully delivered to Event Hub"
        }
    }
}
Write-Output "Activity Logs successfully collected"
