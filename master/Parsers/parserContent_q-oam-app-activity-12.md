#### Parser Content
```Java
{
Name = q-oam-app-activity-12
  DataType = "app-activity"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "SessionDestroy""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-login
  DataType = "app-login"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "Login""""  ]
}

{
  Name = s-oam-app-login
  Vendor = OAM
  Product = Oracle Access Manager
  Lms = Splunk
  DataType = "app-login"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss z"
  Conditions = [ """| AUTHN_""", """OAM_LOGIN |""", """|uid=""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d \w+)\s*\|""",
    """([^\|]*\|){1}\s*({outcome}[^\|]+?)\s*\|""",
    """([^\|]*\|){2}\s*({host}[^\|]+?)\s*\|""",
    """([^\|]*\|){3}\s*({additional_info}[^\|]+?)\s*\|""",
    """([^\|]*\|){5}\s*({auth_method}[^\|]+?)\s*\|""",
    """([^\|]*\|){6}\s*({app}[^\|]+?)_LOGIN\s*\|""",
    """([^\|]*\|){7}\s*uid=({user}[^\|\s]+)""",
  ]
}
```