#### Parser Content
```Java
{
Name = mcafee-security-alert-1
  DataType = "alert"
  Conditions = [ """DetectingProductName=McAfee Host Intrusion Prevention""" ]
  Fields = ${McAfeeParserTemplates.mcafee-dlp-alert.Fields}[
    """\WWorkstation Name=({host}[^,]+)""",
    """\WThreatEventID=({alert_id}\d+)""",
    """\WThreatType=({alert_type}[^,]+)""",
      """,ThreatSourceUserName=(({domain}[^,\\\/]+)[\\\/]+)?({user}[^,\\\/]+),""",
    """\WThreatSourceURL=({malware_url}[^,]+)""",
  ]
}
mcafee-dlp-alert = {
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Direct
    TimeFormat = "epoch"
    Fields = [
      """(t|T)ime=({time}\d+)""",
      """processname=({process}({directory}[^,]*[\\\/]+)?({process_name}[^,\\\/]+))""",
      """username=(({domain}[^,\\\/]+)[\\\/]+)?({user}[^,\\\/]+),""",
      """,sourcehostname=({dest_host}[^,]+)""",
      """,HostName=({dest_host}[^,\.]+)""",
      """,_DB_HOST=({dest_host}[^,\.]+)""",
      """,FilePath=({malware_file_name}[^,]+)"""
      """,threatseverity=({alert_severity}[^,]+)""",
      """,threattype=({alert_type}[^,]+)""",
      """,eventseverity=({alert_severity}[^,]+)""",
      """,ThreatSeverity=({alert_severity}[^,]+)""",
      """,producthostname=({host}[^,]+)""",
      """,DetectingProductHostName=({host}[^,]+)""",
      """,targethostname=({src_host}[^,]+)""",
      """,ThreatSourceProcessName=({process_name}[^,]+)""",
      """,threatname=({alert_name}[^,]+)""",
      """,ThreatName=({alert_name}[^,]+)""",
      """,eventname=({alert_name}[^,]+)""",
      """,Vulnerability Name=({alert_name}[^,]+)"""
    ]

```