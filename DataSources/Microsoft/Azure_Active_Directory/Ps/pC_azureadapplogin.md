#### Parser Content
```Java
{
Name = azure-ad-app-login
  DataType = "app-login"
  Conditions = [ """Microsoft.aadiam""", """Sign-in activity""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Sign-in activity)""",
    """userPrincipalName":"({user_email}[^",]{1,2000})""",
    """userId":"({user_uid}[^",]{1,2000})""",
    """errorCode":({error_code}\d{1,100})""",
    """Level":({alert_severity}\d{1,100})""",
    """appDisplayName":"\s{0,100}({app}[^",]{1,2000})""",
    """deviceDetail.+?displayName":"({object}[^",]{1,2000})""",
    """userAgent":"({user_agent}.+?)"?,\w+":""",
    """"failureReason":"({failure_reason}[^"]{1,200})"""
  ]

azure-ad-activity = {
   Vendor = Microsoft
   Product = Azure Active Directory
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