#### Parser Content
```Java
{
Name = azure-ad-account-password-change-1
  DataType = "password-change"
  Conditions = [ """Microsoft.aadiam""", """Self-service password reset""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Self-service password reset)""",
    """targetResources":.+?userPrincipalName":"({target_user}[^",]+)""",
    """targetResources":.+?id":"({user_sid}[^",]+)"""
  ]
}
azure-ad-activity = {
   Vendor = Microsoft
   Product = Microsoft Azure Active Directory
   Lms = QRadar
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
   Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z)""",
      """initiatedBy":.+?userPrincipalName":"({user_email}[^",]+)""",
      """initiatedBy":.+?id":"({user_uid}[^",]+)""",
      """callerIpAddress":"({src_ip}[^",]+)""",
      """operationName":"({activity}[^",]+)""",
      """result":"(notEnabled|notApplied|({outcome}[^",]+))""",
      """category":"({category}[^",]+)"{0,20},correlationId"""",
      """"app":\{.*?displayName":"({app}[^",]+)""",
      """loggedByService":"({app}[^",]+)"""
   ]

```