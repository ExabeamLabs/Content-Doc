#### Parser Content
```Java
{
Name = mcafee-dlp-mem-dev
  DataType = "usb-activity"
  Conditions = [ """RulesToDisplay=""", """Portable and Memory Devices""", """ViolationUTCTime=""", """Destination=""", """Username=""", """ViolationTimezone=""", """ViolationLocalTime=""" ]

  Fields = ${McAfeeParserTemplates.mcafee-dlp-activity.Fields} [
    """,\sDestination="*({device_type}[^"]+)"*,\s"""
  ]
}
```