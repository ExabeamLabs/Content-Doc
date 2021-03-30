#### Parser Content
```Java
{
Name = ms-azure-eventhubs-login
  DataType = "app-login"
  Conditions = [ """eventHubsAzureRecord""", """Sign-in activity""" ]
  Fields = ${MSParserTemplates.ms-azure-eventhubs-activity.Fields} [
    """"+identity"+:"+({user_fullname}[^",]+)"+""",
    """"+identity"+:"+({user_lastname}[^",]+),\s*({user_firstname}[^",\/]+)(\/[^"]*)?"""",
    """"+userId"+:"+({user_id}[^"]+)"+""",
    """"+appDisplayName"+:"+({app}[^"]+)"+""",
    """"+operatingSystem"+:"+({os}[^"]+)"+""",
    """"+browser"+:"+({browser}[^"]+)"+""",
    """"+location"+:(\{"+geoCoordinates"+:\{\}\}|({additional_info}\{.*?\}))"""
    """"+failureReason"+:"+({failure_reason}[^"]+)"+"""
  ]
}
ms-azure-eventhubs-activity = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = QRadar
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"+callerIpAddress"+:"+(<null>|({src_ip}[^"]+))"+""",
    """"+initiatedBy.*?"+userPrincipalName"+:"+({user_email}[^"]+?)"+"""
    """"+targetResources.*?"+displayName"+:"+({object}[^"]+?)"+""",
    """"+targetResources.*?"+userPrincipalName"+:"+({object}[^"]+?)"+"""
    """"+targetResources.*?"+displayName"+:"+.*?\.DisplayName"+.*?"+newValue"+:[\\"]*(null|({target}[^"\\]+))["\\]*"""
    """"+time"+:"+({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}\w+)"+"""
    """"+operationName"+:"+({activity}[^"]+)"+""",
    """"+result"+:"+({outcome}[^"]+)"+""",
    """({app}eventHubsAzureRecord)""" 
  ]

```