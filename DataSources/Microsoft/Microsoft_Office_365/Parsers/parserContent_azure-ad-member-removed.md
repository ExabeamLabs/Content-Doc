#### Parser Content
```Java
{
Name = azure-ad-member-removed
  DataType = "member-removed"
  Conditions = [ """Microsoft.aadiam""", """Remove member from group""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Remove member from group)""",
    """targetResources":.+?Group\.DisplayName.+?newValue":"\\*"({group_name}[^\\"]{1,2000})""",
    """targetResources":.+?id":"({account_id}[^",]{1,2000})"""
  ]
}
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
   ]

```