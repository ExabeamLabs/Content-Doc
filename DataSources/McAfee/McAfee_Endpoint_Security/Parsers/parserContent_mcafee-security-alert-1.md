#### Parser Content
```Java
{
Name = mcafee-security-alert-1
  DataType = "alert"
  Conditions = [ """DetectingProductName=McAfee Host Intrusion Prevention""" ]
  Fields = ${McAfeeParserTemplates.mcafee-dlp-alert.Fields}[
    """\WWorkstation Name=({host}[^,]{1,2000})""",
    """\WThreatEventID=({alert_id}\d{1,100})""",
    """\WThreatType=({alert_type}[^,]{1,2000})""",
      """,ThreatSourceUserName=(({domain}[^,\\\/]{1,2000})[\\\/]{1,2000})?({user}[^,\\\/]{1,2000}),""",
    """\WThreatSourceURL=({malware_url}[^,]{1,2000})""",
  ]
}
mcafee-dlp-alert = {
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Direct
    TimeFormat = "epoch"
    Fields = [
      """(t|T)ime=({time}\d{1,100})""",
      """processname=({process}({directory}[^,]{0,2000}[\\\/]{1,2000})?({process_name}[^,\\\/]{1,2000}))""",
      """username=(({domain}[^,\\\/]{1,2000})[\\\/]{1,2000})?({user}[^,\\\/]{1,2000}),""",
      """,sourcehostname=({dest_host}[^,]{1,2000})""",
      """,HostName=({dest_host}[^,\.]{1,2000})""",
      """,_DB_HOST=({dest_host}[^,\.]{1,2000})""",
      """,FilePath=({malware_file_name}[^,]{1,2000})"""
      """,threatseverity=({alert_severity}[^,]{1,2000})""",
      """,threattype=({alert_type}[^,]{1,2000})""",
      """,eventseverity=({alert_severity}[^,]{1,2000})""",
      """,ThreatSeverity=({alert_severity}[^,]{1,2000})""",
      """,producthostname=({host}[^,]{1,2000})""",
      """,DetectingProductHostName=({host}[^,]{1,2000})""",
      """,targethostname=({src_host}[^,]{1,2000})""",
      """,ThreatSourceProcessName=({process_name}[^,]{1,2000})""",
      """,threatname=({alert_name}[^,]{1,2000})""",
      """,ThreatName=({alert_name}[^,]{1,2000})""",
      """,eventname=({alert_name}[^,]{1,2000})""",
      """,Vulnerability Name=({alert_name}[^,]{1,2000})"""
    ]

```