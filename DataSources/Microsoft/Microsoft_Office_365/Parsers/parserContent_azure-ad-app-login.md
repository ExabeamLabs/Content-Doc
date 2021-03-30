#### Parser Content
```Java
{
Name = azure-ad-app-login
  DataType = "app-login"
  Conditions = [ """Microsoft.aadiam""", """Sign-in activity""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Sign-in activity)""",
    """userPrincipalName":"({user_email}[^",]+)""",
    """userId":"({user_uid}[^",]+)""",
    """errorCode":({error_code}\d+)""",
    """Level":({alert_severity}\d+)""",
    """appDisplayName":"\s*({app}[^",]+)""",
    """deviceDetail.+?displayName":"({object}[^",]+)""",
    """browser":"({browser}[^",]+)""",
    """userAgent":"({user_agent}.+?)"?,\w+":""",
    """operatingSystem.+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)"""
  ]
}
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