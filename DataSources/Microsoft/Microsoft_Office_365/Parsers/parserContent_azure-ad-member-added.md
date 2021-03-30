#### Parser Content
```Java
{
Name = azure-ad-member-added
  DataType = "member-added"
  Conditions = [ """Microsoft.aadiam""", """Add member to group""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Add member to group)""",
    """targetResources"+:\[\{([^,]+,){3}"+userPrincipalName"+:"+({target_user}[^"]+)"""",
    """targetResources"+:\[\{[^\}]+\}
azure-ad-activity = {
   Vendor = Microsoft
   Product = Microsoft Azure Active Directory
   Lms = QRadar
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
   Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z)""",
      """initiatedBy":.+?userPrincipalName":"({user_email}[^",]+)""",
      """initiatedBy":.+?id":"({user_uid}[^",]+)""",
      """callerIpAddress":"({src_ip}[^",]+)""",
      """operationName":"({activity}[^",]+)""",
      """result":"(notEnabled|notApplied|({outcome}[^",]+))""",
      """category":"({category}[^",]+)"*,correlationId"""",
      """"app":\{.*?displayName":"({app}[^",]+)""",
      """loggedByService":"({app}[^",]+)"""
   ]

```