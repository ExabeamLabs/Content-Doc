#### Parser Content
```Java
{
Name = azure-keyvault-activity
   Vendor = Microsoft
   Product = Microsoft Azure
   Lms = Direct
   DataType = "azure-general-activity"
   TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
   Conditions = [ """Type":"AzureDiagnostics""", """ResourceProvider":"MICROSOFT.KEYVAULT""", """OperationName""" ] 
 
azure-workspacekeyault-json = {
    Vendor = Microsoft
    Product = Microsoft Azure
    Lms = Direct
    DataType = "azure-general-activity"
    TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
    Fields = [
    """"{1,20}TimeGenerated"{1,20}:\s{0,200}"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z?)"{1,20}""",
    """"{1,20}TenantId"{1,20}:\s{0,100}"{1,20}({tenant_id}[^"]{1,2000})"{1,20}""",
    """"{1,20}OperationName"{1,20}:\s{0,100}"{1,20}({operation}[^"]{1,2000})"{1,20}""",
    """"{1,20}CorrelationId"{1,20}:\s{0,100}"{1,20}({correlation_id}[^"]{1,2000})"{1,20}""",
    """"{1,20}OperationVersion"{1,20}:\s{0,100}"{1,20}({operation_version}[^"]{1,2000})"{1,20}""",
    """"{1,20}Category"{1,20}:\s{0,100}"{1,20}({operation_type}[^"]{1,2000})"{1,20}""",
    """"{1,20}Type"{1,20}:\s{0,100}"{1,20}({log_type}[^"]{1,2000})"{1,20}""",
    """"{1,20}ResourceId"{1,20}:\s{0,100}"{1,20}({resource}({resource_path}[^"]{1,2000})\/({resource_name}[^"]{1,2000})|[^"]{1,2000})"{1,20}""",
    """"{1,20}ResultType"{1,20}:\s{0,100}"{1,20}({result_code}[^"]{1,2000})"{1,20}""",
    """"{1,20}ResultDescription"{1,20}:\s{0,100}"{1,20}({failure_reason}[^"]{1,2000})"{1,20}""",
    """"{1,20}Resource"{1,20}:\s{0,100}"{1,20}({resource_name}[^"]{1,2000})"{1,20}""",
    """"{1,20}ResourceGroup"{1,20}:\s{0,100}"{1,20}({resource_group}[^"]{1,2000})"{1,20}""",
    """"{1,20}ResourceProvider"{1,20}:\s{0,100}"{1,20}({service}[^"]{1,2000})"{1,20}""",
    """"{1,20}SubscriptionId"{1,20}:\s{0,100}"{1,20}({subscription_id}[^"]{1,2000})"{1,20}""",
    """"{1,20}ResourceType"{1,20}:\s{0,100}"{1,20}({resource_type}[^"]{1,2000})"{1,20}""",
    """"{1,20}requestUri_s"{1,20}:\s{0,100}"{1,20}({full_url}[^"]{1,2000})"{1,20}""",
    """"{1,20}CallerIPAddress"{1,20}:\s{0,100}"{1,20}({src_ip}[^"]{1,2000})"{1,20}""",
    """"{1,20}id_s"{1,20}:\s{0,100}"{1,20}({creds_path}[^"]{1,2000}\/({creds_name}[^\/"]{1,2000})|[^"]{1,2000})"{1,20}""",
    """"{1,20}clientInfo"{1,20}:\s{0,100}"{1,20}({user_agent}[^"]{1,2000})"{1,20}""",
    """"{1,20}clientInfo_s"{1,20}:\s{0,100}"{1,20}({user_agent}[^"]{1,2000})"{1,20}""",
    """"{1,20}identity_claim_upn_s"{1,20}:\s{0,200}"{1,20}({user}[^"]{1,2000}@({domain}[^"]{1,2000})|[^"]{1,2000})""",
    """"{1,20}keyProperties_type_s"{1,20}:\s{0,100}"{1,20}({key_type}[^"]{1,2000})"{1,20}""",
    ]
    DupFields = [ "operation->operation_name", "resource_name->keyvault"
}
```