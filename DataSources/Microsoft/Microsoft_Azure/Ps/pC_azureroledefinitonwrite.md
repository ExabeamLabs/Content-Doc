#### Parser Content
```Java
{
Name = azure-roledefiniton-write
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct
  DataType = "azure-role-write"
  TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
  Conditions = [ """localizedValue":"Create or update custom role definition""" ]
  Fields = ${MSParserTemplates.azure-activity-json.Fields}[
    """"{1,20}requestbody"{1,20}:[^\}]+"{1,20}roleName\\?"{1,20}:\s{0,100}\\?"{1,20}({role}[^"]{1,2000})\\"{1,20}""",
    """"{1,20}requestbody"{1,20}:[^\}]+"{1,20}description\\?"{1,20}:\s{0,100}\\?"{1,20}({description}[^"]{1,2000})\\"{1,20}""",
    """"{1,20}requestbody"{1,20}:[^\}]+"{1,20}assignableScopes\\?"{1,20}:\s{0,100}\[({assignble_scope}[^\]\[]{1,2000})\]""",
    """"{1,20}requestbody"{1,20}:[^\}]+"{1,20}permissions\\?"{1,20}:\s{0,100}\[({role_definition}\{[^;]+\})\]""",
    """"{1,20}requestbody"{1,20}:[^\}]+"{1,20}actions\\?"{1,20}:\s{0,100}\[({allowed_permissions}[^\]]{1,2000})\]""",
    """"{1,20}requestbody"{1,20}:[^\}]+"{1,20}dataActions\\?"{1,20}:\s{0,100}\[({allowed_data_actions}[^\]]{1,2000})\]""",
    """"{1,20}requestbody"{1,20}:[^\}]+"{1,20}notDataActions\\?"{1,20}:\s{0,100}\[({denied_data_actions}[^\]]{1,2000})\]""",
  ]

azure-activity-json = {
    Vendor = Microsoft
    Product = Microsoft Azure
    Lms = Direct
    DataType = "azure-general-activity"
    TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
    Fields = [
      """"{1,20}eventTimestamp"{1,20}:\s{0,200}"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z?)"{1,20}""",
      """"{1,20}authorization"{1,20}:[^\}]+scope"{1,20}:\s{0,200}"{1,20}({authorization_scope}[^"]{1,2000})""", 
      """"{1,20}caller"{1,20}:\s{0,200}"{1,20}(({user_email}[^@]{1,2000}@({email_domain}[^\s"]{1,2000}))|({user}[^\s"]{1,2000}))""",
      """"{1,20}claims"{1,20}:[^\}]+ipaddr"{1,20}:\s{0,200}"{1,20}({src_ip}[^"]{1,2000})"{1,20}""",
      """"{1,20}correlationId"{1,20}:\s{0,200}"{1,20}({correlation_id}[^"]{1,2000})""",
      """"{1,20}eventName"{1,20}:[^\}]+value"{1,20}:\s{0,200}"{1,20}({operation_first}BeginRequest)"{1,20}""",
      """"{1,20}eventName"{1,20}:[^\}]+value"{1,20}:\s{0,200}"{1,20}({operation_last}EndRequest)"{1,20}""",
      """"{1,20}category"{1,20}:[^\}]+value"{1,20}:\s{0,200}"{1,20}({log_type}[^"]{1,2000})"{1,20}""",
      """"{1,20}operationName"{1,20}:[^\}]+value"{1,20}:\s{0,200}"{1,20}({operation}[^"]{1,2000})"{1,20}""",
      """"{1,20}operationName"{1,20}:[^\}]+localizedValue"{1,20}:\s{0,200}"{1,20}({operation_name}[^"]{1,2000})"{1,20}""",
      """"{1,20}resourceGroupName"{1,20}:\s{0,100}"{1,20}({resource_group}[^"]{1,2000})"{1,20}""",
      """"{1,20}resourceProviderName"{1,20}:[^\}]+value"{1,20}:\s{0,200}"{1,20}({service}[^"]{1,2000})"{1,20}""",
      """"{1,20}resourceType"{1,20}:[^\}]+value"{1,20}:\s{0,200}"{1,20}({resource_type}[^"]{1,2000})"{1,20}""",
      """"{1,20}resourceId"{1,20}:\s{0,100}"{1,20}({resource}({resource_path}[^"]{1,2000})\/({resource_name}[^"]{1,2000})|[^"]{1,2000})"{1,20}""",
      """"{1,20}status"{1,20}:[^\}]+value"{1,20}:\s{0,200}"{1,20}({status}[^"]{1,2000})"{1,20}""",
      """"{1,20}subscriptionId"{1,20}:\s{0,100}"{1,20}({subscription_id}[^"]{1,2000})"{1,20}""",
      """"{1,20}tenantId"{1,20}:\s{0,100}"{1,20}({tenant_id}[^"]{1,2000})"{1,20}""",
      """"{1,20}properties[^\}]+statusMessage[^\}]+error[^\}]+code\\*"{1,20}:\s{0,200}\\+"{1,20}({result_code}[^\\]{1,2000})""",
      """"{1,20}properties[^\}]+statusMessage[^\}]+error[^\}]+message\\*"{1,20}:\s{0,200}\\+"{1,20}({failure_reason}[^"]{1,2000})\\""",
      
}
```