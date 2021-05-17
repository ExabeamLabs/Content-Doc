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
     """UserName="({domain}[^\\]{1,2000})\\({user}[^"]{1,2000})"""",
     """ComputerName="({src_host}[^"]{1,2000})"""",
     """FocusDisplay="({printer_name}[^"]{1,2000})"""",
     """XmlEvidence.+?FILE_NAME.+?>({object}[^<]{1,2000})<""",
     """XmlEvidence.+?FILE_NAME.+?size="({bytes}[^"]{1,2000})""",
     """({activity}Printing)""",
     """ProcessInfo_FileName="({process_name}[^"]{1,2000})""",
     """ReactionSet_DisplayName="({outcome}[^"]{1,2000})""",
     """RuleIDSet_DisplayName="({additional_info}[^"]{1,2000})""",
     """UTCTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """exabeam_host=({host}[^\s]{1,2000})"""
  ]
}
```