#### Parser Content
```Java
{
Name = mcafee-security-alert-4
  DataType = "alert"
  Conditions = [ """productname=VirusScan Enterprise""" ]
  Fields = ${McAfeeParserTemplates.mcafee-dlp-alert.Fields}[
    """serverhostname=({host}[^,]+)""",
  ]
}
mcafee-dlp-alert = {
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Direct
    TimeFormat = "epoch"
    Fields = [
      """(t|T)ime=({time}\d{1,100})""",
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