#### Parser Content
```Java
{
Name = mcafee-dlp-print-2
  DataType = "print-activity"
  Conditions = [ """RulesToDisplay="Printer""", """ViolationUTCTime=""", """Destination=""", """Username=""", """ViolationTimezone=""", """ViolationLocalTime=""" ]

  Fields =${McAfeeParserTemplates.mcafee-dlp-activity.Fields} [
     """,\sDestination="*({printer_name}[^"]+)"*,\s""",
     """,\sFileName="*({object}.+?)"*,\s"""
  ]
}
```