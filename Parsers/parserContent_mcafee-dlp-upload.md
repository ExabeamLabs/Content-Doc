#### Parser Content
```Java
{
Name = mcafee-dlp-upload
  DataType = "dlp-alert"
  Conditions = [ """ViolationUTCTime=""", """Destination=""", """RulesToDisplay=""", """Username=""", """ViolationTimezone=""", """ViolationLocalTime=""" ]

  Fields =${McAfeeParserTemplates.mcafee-dlp-activity.Fields} [
     """\,\sDestination="*({target}[^"]+)"*,\s"""
  ]
}
```