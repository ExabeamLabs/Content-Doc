#### Parser Content
```Java
{
Name = azure-ad-member-removed
  DataType = "member-removed"
  Conditions = [ """Microsoft.aadiam""", """Remove member from group""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Remove member from group)""",
    """targetResources":.+?Group\.DisplayName.+?newValue":"\\*"({group_name}[^\\"]+)""",
    """targetResources":.+?id":"({account_id}[^",]+)"""
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