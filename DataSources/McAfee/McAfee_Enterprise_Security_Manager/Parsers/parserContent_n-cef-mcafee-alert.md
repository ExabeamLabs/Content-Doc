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
    """\Wrt=({time}\d{1,100})""",
    """\Wproto=({protocol}.*?)\s{1,100}(\w+=|$)""",
    """\Wcat=({alert_type}.*?)\s{1,100}(\w+=|$)""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wshost=({src_host}.*?)\s{1,100}(\w+=|$)""",
    """\WnitroCategory=({threat_category}.*?)\s{1,100}(\w+=|$)""",
    """\Wsntdom=({domain}.*?)\s{1,100}(\w+=|$)"""
  ]
}
```