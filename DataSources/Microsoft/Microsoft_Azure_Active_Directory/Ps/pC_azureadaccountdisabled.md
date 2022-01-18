#### Parser Content
```Java
{
Name = azure-ad-account-disabled
  DataType = "account-disabled"
  Conditions = [ """Microsoft.aadiam""", """Disable account""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Disable account)""",
    """targetResources":.+?userPrincipalName":"({target_user}[^",]{1,2000})""",
    """targetResources":.+?id":"({user_sid}[^",]{1,2000})"""
  ]

azure-ad-activity = {
   Vendor = Microsoft
   Product = Microsoft Azure Active Directory
   Lms = QRadar
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
   Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z)""",
      """initiatedBy":.+?userPrincipalName":"({user_email}[^",]{1,2000})""",
      """initiatedBy":.+?id":"({user_uid}[^",]{1,2000})""",
      """callerIpAddress":"({src_ip}[^",]{1,2000})""",
      """operationName":"({activity}[^",]{1,2000})""",
      """result":"(notEnabled|notApplied|({outcome}[^",]{1,2000}))""",
      """category":"({category}[^",]{1,2000})"{0,20},correlationId"""",
      """"app":\{.*?displayName":"({app}[^",]{1,2000})""",
      """loggedByService":"({app}[^",]{1,2000})"""
   
}
```