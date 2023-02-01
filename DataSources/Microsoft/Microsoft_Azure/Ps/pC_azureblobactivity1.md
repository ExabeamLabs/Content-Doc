#### Parser Content
```Java
{
Name = azure-blob-activity1
   Vendor = Microsoft
   Product = Microsoft Azure
   Lms = Direct
   DataType = "azure-general-activity"
   TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
   Conditions = [ """Type":"StorageBlobLogs""", """OperationName""" ] 
 
azure-workspaceblob-json = {
    Vendor = Microsoft
    Product = Microsoft Azure
    Lms = Direct
    DataType = "azure-general-activity"
    TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
    Fields = [
    """"{1,20}TimeGenerated"{1,20}:\s{0,200}"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z?)"{1,20}""",
    """"{1,20}TenantId"{1,20}:\s{0,100}"{1,20}({tenant_id}[^"]{1,2000})"{1,20}""",
    """"{1,20}AccountName"{1,20}:\s{0,100}"{1,20}({storage_account}[^"]{1,2000})"{1,20}""",
    """"{1,20}Location"{1,20}:\s{0,100}"{1,20}({region}[^"]{1,2000})"{1,20}""",
    """"{1,20}Protocol"{1,20}:\s{0,100}"{1,20}({protocol}[^"]{1,2000})"{1,20}""",
    """"{1,20}OperationName"{1,20}:\s{0,100}"{1,20}({operation}[^"]{1,2000})"{1,20}""",
    """"{1,20}AuthenticationType"{1,20}:\s{0,100}"{1,20}({authentication_type}[^"]{1,2000})"{1,20}""",
    """"{1,20}StatusCode"{1,20}:\s{0,100}"{1,20}({result_code}[^"]{1,2000})"{1,20}""",
    """"{1,20}StatusText"{1,20}:\s{0,100}"{1,20}({status}[^"]{1,2000})"{1,20}""",
    """"{1,20}Uri"{1,20}:\s{0,100}"{1,20}({full_url}({file_path}[^"]{1,2000}\/({file_name}[^\?"]{1,2000}))[^"]{0,2000}|[^"]{1,2000})"{1,20}""",
    """"{1,20}CallerIpAddress"{1,20}:\s{0,100}"{1,20}({src_ip}[^"]{1,2000})"{1,20}""",
    """"{1,20}CorrelationId"{1,20}:\s{0,100}"{1,20}({correlation_id}[^"]{1,2000})"{1,20}""",
    """"{1,20}SchemaVersion"{1,20}:\s{0,100}"{1,20}({schema_version}[^"]{1,2000})"{1,20}""",
    """"{1,20}OperationVersion"{1,20}:\s{0,100}"{1,20}({operation_version}[^"]{1,2000})"{1,20}""",
    """"{1,20}UserAgentHeader"{1,20}:\s{0,100}"{1,20}({user_agent}[^"]{1,2000})"{1,20}""",
    """"{1,20}ReferrerHeader"{1,20}:\s{0,100}"{1,20}({referrer}[^"]{1,2000})"{1,20}""",
    """"{1,20}RequestBodySize"{1,20}:\s{0,100}({bytes_in}\d{1,1000})""",
    """"{1,20}ResponseBodySize"{1,20}:\s{0,100}({bytes_out}\d{1,1000})""",
    """"{1,20}LastModifiedTime"{1,20}:\s{0,100}"{1,20}({file_modify_time}[^"]{1,2000})"{1,20}""",
    """"{1,20}Category"{1,20}:\s{0,100}"{1,20}({operation_type}[^"]{1,2000})"{1,20}""",
    """"{1,20}Type"{1,20}:\s{0,100}"{1,20}({log_type}[^"]{1,2000})"{1,20}""",
    """"{1,20}RequesterUpn"{1,20}:\s{0,200}"{1,20}({user}[^"]{1,2000}@({domain}[^"]{1,2000})|[^"]{1,2000})""",
    ]
    DupFields = [ "operation->operation_name", "storage_account->dest_host" 
}
```