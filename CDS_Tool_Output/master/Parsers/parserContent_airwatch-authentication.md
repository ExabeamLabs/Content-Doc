#### Parser Content
```Java
{
Name = airwatch-authentication
  DataType = "authentication-successful" 
  Conditions = [ """AirWatch""", """Event Category:"Authentication"""", """Event:""""]
  Fields = ${AirWatchParserTemplates.airwatch-auth-activity.Fields}[]
  DupFields = ["event_type->auth_type"]
}
${AirWatchParserTemplates.airwatch-auth-activity}{
  Name = airwatch-auth-successful
  DataType = "authentication-successful"
  Conditions = [ """AirWatch""", """Event Category:"Login"""", """Event:""""]
}
${AirWatchParserTemplates.airwatch-auth-activity}{
  Name = airwatch-security-alerts
  DataType = "security-alerts"
  Conditions = [ """AirWatch""", """Event Category:"""", """Event:"""" ]

}

{
  Name = anywhere365-app-activity
  Conditions = [""" CallReceivedOnEndpoint: """]
  Vendor = Anywhere365
  Product = Anywhere365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """\s({log_id}\w+-\w+-\w+-\w+-\w+)\s""",
    """CallReceivedOnEndpoint:\s'sip:({recipient}[^@]+[^\.]+\.[^,\s;']+)""",
  ]
}
```