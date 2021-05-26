#### Parser Content
```Java
{
Name = raw-scep-epp-alert
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"SystemCenterEndpointProtection"""" ]
  Fields = [
    """exabeam_host=(\S+@\s{0,100})?({host}[^\s]{1,2000})""",
    """\sdest_name="{1,20}({src_host}[^\s"]{1,2000})""",
    """(Timestamp: |Timestamp=)"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100} \d\d:\d\d:\d\d)""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """((?i)RowID)"?:\s{0,100}"{1,20}({alert_id}[^"]{1,2000})""",
    """((?i)TargetHost)"?:\s{0,100}"{1,20}({dest_host}[^"]{1,2000})""",
    """((?i)TargetUser"?:\s{0,100}|user=)"{1,20}(({domain}[^\\]{1,2000})\\+)?({user}[^"\\]{1,2000})""",
    """((?i)TargetResource)"?:\s{0,100}"{1,20}({additional_info}[^"]{1,2000})""",
    """((?i)ClassificationType"?:\s{0,100}|signature=)"{1,20}({alert_name}[^"]{1,2000})""",
    """((?i)ClassificationSeverity"?:\s{0,100}|severity=)"{1,20}({alert_severity}[^"]{1,2000})""",
    """((?i)ClassificationCategory"?:\s{0,100}|category=)"{1,20}({alert_type}[^"]{1,2000})""",
    """\sfile_path="{1,20}({malware_url}[^",]{1,2000})""",
    """(SrcAddress: |src=)"{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """((?i)TargetProcess)"?(:|=)\s{0,100}"{1,20}({process}[^"]{1,2000}\\({process_name}[^"]{1,2000}))""",
  ]
  DupFields = ["host->dest_host"]
}
```