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
```