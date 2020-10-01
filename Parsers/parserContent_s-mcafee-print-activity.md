#### Parser Content
```Java
{
Name = s-mcafee-print-activity
  Vendor = McAfee
  Product = McAfee DLP
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """OUTGOING_PRINTER""", """DLP: Printing Protection""" ]
  Fields = [
     """UserName="({domain}[^\\]+)\\({user}[^"]+)"""",
     """ComputerName="({src_host}[^"]+)"""",
     """FocusDisplay="({printer_name}[^"]+)"""",
     """XmlEvidence.+?FILE_NAME.+?>({object}[^<]+)<""",
     """XmlEvidence.+?FILE_NAME.+?size="({bytes}[^"]+)""",
     """({activity}Printing)""",
     """ProcessInfo_FileName="({process_name}[^"]+)""",
     """ReactionSet_DisplayName="({outcome}[^"]+)""",
     """RuleIDSet_DisplayName="({additional_info}[^"]+)""",
     """UTCTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """exabeam_host=({host}[^\s]+)"""
  ]
}
```