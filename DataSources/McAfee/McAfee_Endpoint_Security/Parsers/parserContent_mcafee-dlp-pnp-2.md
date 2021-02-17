#### Parser Content
```Java
{
Name = mcafee-dlp-pnp-2
  DataType = "usb-activity"
  Conditions = [ """RulesToDisplay="Plug and Play""", """ViolationUTCTime=""", """Destination=""", """Username=""", """ViolationTimezone=""", """ViolationLocalTime=""" ]

  Fields = ${McAfeeParserTemplates.mcafee-dlp-activity.Fields} [
    """,\sDestination="*({device_type}[^"]+)"*,\s"""
  ]
}
```