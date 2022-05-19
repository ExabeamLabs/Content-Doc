#### Parser Content
```Java
{
Name = azure-ad-account-password-change-2
  DataType = "password-change"
  Conditions = [ """"Resource":"Microsoft.aadiam"""", """"OperationName":"Change user password"""",  """"TenantId":"""", """"Type":"AuditLogs""""]
  Fields = ${MSParserTemplates.azure-ad-activity-1.Fields} [
    """({event_name}Change user password)""",
    """TargetResources":\[\{[^\}]{1,2000}?userPrincipalName":"({target_user}[^@"]{1,2000}@[^"]{1,2000})","ipAddress""""
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