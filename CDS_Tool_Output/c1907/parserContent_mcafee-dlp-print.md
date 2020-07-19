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

${McAfeeParserTemplates.mcafee-dlp-activity}{
  Name = mcafee-dlp-print-2
  DataType = "print-activity"
  Conditions = [ """RulesToDisplay="Printer""", """ViolationUTCTime=""", """Destination=""", """Username=""", """ViolationTimezone=""", """ViolationLocalTime=""" ]

  Fields =${McAfeeParserTemplates.mcafee-dlp-activity.Fields} [
     """,\sDestination="*({printer_name}[^"]+)"*,\s""",
     """,\sFileName="*({object}.+?)"*,\s"""
  ]
}

${McAfeeParserTemplates.mcafee-dlp-activity}{
  Name = mcafee-dlp-upload
  DataType = "dlp-alert"
  Conditions = [ """ViolationUTCTime=""", """Destination=""", """RulesToDisplay=""", """Username=""", """ViolationTimezone=""", """ViolationLocalTime=""" ]

  Fields =${McAfeeParserTemplates.mcafee-dlp-activity.Fields} [
     """\,\sDestination="*({target}[^"]+)"*,\s"""
  ]
}

${McAfeeParserTemplates.mcafee-usb-insert}{
  Name = mcafee-usb-insert
  Conditions = [ """<DeviceSN>""", """<EventID>20500</EventID>""" ]
}
```