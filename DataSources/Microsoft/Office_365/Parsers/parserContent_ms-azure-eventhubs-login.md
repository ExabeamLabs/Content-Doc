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
```