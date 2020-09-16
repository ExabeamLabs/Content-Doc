#### Parser Content
```Java
{
Name = n-cef-mcafee-alert
  Vendor = McAfee
  Product = McAfee Enterprise Security Manager
  Lms = NitroCefSyslog
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = [ """|McAfee|ESM|""", """deviceExternalId=McAfee_NSM_OPMNSMP3""" ]
  Fields = [
    """\|McAfee\|ESM\|([^|]+?\|){2}({alert_name}[^|]+)\|""",
    """\Wrt=({time}\d+)""",
    """\Wproto=({protocol}.*?)\s+(\w+=|$)""",
    """\Wcat=({alert_type}.*?)\s+(\w+=|$)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wspt=({src_port}\d+)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wshost=({src_host}.*?)\s+(\w+=|$)""",
    """\WnitroCategory=({threat_category}.*?)\s+(\w+=|$)""",
    """\Wsntdom=({domain}.*?)\s+(\w+=|$)"""
  ]
}
```