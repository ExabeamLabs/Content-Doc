#### Parser Content
```Java
{
Name = mcafee-dlp-rem-stor
  DataType = "usb-activity"
  Conditions = [ """RulesToDisplay=""", """(Removable Storage)""", """ViolationUTCTime=""", """Destination=""", """Username=""", """ViolationTimezone=""", """ViolationLocalTime=""" ]

  Fields = ${McAfeeParserTemplates.mcafee-dlp-activity.Fields} [
    """,\sDestination="*({device_type}[^"]+)"*,\s"""
  ]
}
```