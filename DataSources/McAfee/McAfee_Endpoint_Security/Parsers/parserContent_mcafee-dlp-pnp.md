#### Parser Content
```Java
{
Name = mcafee-dlp-pnp
  DataType = "usb-activity"
  Conditions = [ """RulesToDisplay="PNP""", """ViolationUTCTime=""", """Destination=""", """Username=""", """ViolationTimezone=""", """ViolationLocalTime=""" ]

  Fields = ${McAfeeParserTemplates.mcafee-dlp-activity.Fields} [
    """,\sDestination="*({device_type}[^"]+)"*,\s"""
  ]
}
```