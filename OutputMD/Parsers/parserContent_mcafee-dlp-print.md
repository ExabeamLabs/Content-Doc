#### Parser Content
```Java
{
Name = mcafee-dlp-print
  DataType = "print-activity"
  Conditions = [ """(Printer)""", """RulesToDisplay=""", """ViolationUTCTime=""", """Destination=""", """Username=""", """ViolationTimezone=""", """ViolationLocalTime=""" ]

  Fields = ${McAfeeParserTemplates.mcafee-dlp-activity.Fields} [
     """,\sDestination="*({printer_name}[^"]+)*",\s""",
     """,\sFileName="*({object}.+?)"*,\s"""
  ]
}
```