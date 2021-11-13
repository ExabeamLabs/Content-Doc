#### Parser Content
```Java
{
Name = azure-ad-member-added-1
  DataType = "member-added"
  Conditions = [ """"Resource":"Microsoft.aadiam"""", """"OperationName":"Add member to group"""", """"TenantId":"""", """"Type":"AuditLogs""""]
  Fields = ${MSParserTemplates.azure-ad-activity-1.Fields} [
    """({event_name}Add member to group)""", 
    """Group\.DisplayName\\[^}]{1,1000}"newValue\\":[\\"]{1,1000}({group_name}[^"\\]{1,2000})""",
    """"TargetResources":"\[\{\\"id\\":\\"({account_id}[^"\\]{1,2000})"""
  ]

azure-ad-activity-1 = {
   Vendor = Microsoft
   Product = Azure Active Directory
   Lms = Direct
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
   Fields = [
     """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",    
     """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)""",
     """"userPrincipalName(\\)?":(\\)?"({user_email}[^"\\]{1,2000})""",
     """"OperationName":"({activity}[^"]{1,2000})"""",
     """"Result":"({outcome}[^",]{1,2000})"""",
     """"Category":"({category}[^"]{1,2000})"""",
     """"app":\{[^,]{1,100},"displayName":"({app}[^"]{1,2000})"""", 
     """"LoggedByService":"({app}[^"]{1,2000})""""
   
}
```