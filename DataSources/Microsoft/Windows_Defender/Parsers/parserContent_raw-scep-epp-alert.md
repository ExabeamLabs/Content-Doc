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
    """exabeam_host=(\S+@\s{0,100})?({host}[^\s]+)""",
    """\sdest_name="{1,20}({src_host}[^\s"]+)""",
    """(Timestamp: |Timestamp=)"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100} \d\d:\d\d:\d\d)""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """((?i)RowID)"?:\s{0,100}"{1,20}({alert_id}[^"]+)""",
    """((?i)TargetHost)"?:\s{0,100}"{1,20}({dest_host}[^"]+)""",
    """((?i)TargetUser"?:\s{0,100}|user=)"{1,20}(({domain}[^\\]+)\\+)?({user}[^"\\]+)""",
    """((?i)TargetResource)"?:\s{0,100}"{1,20}({additional_info}[^"]+)""",
    """((?i)ClassificationType"?:\s{0,100}|signature=)"{1,20}({alert_name}[^"]+)""",
    """((?i)ClassificationSeverity"?:\s{0,100}|severity=)"{1,20}({alert_severity}[^"]+)""",
    """((?i)ClassificationCategory"?:\s{0,100}|category=)"{1,20}({alert_type}[^"]+)""",
    """\sfile_path="{1,20}({malware_url}[^",]+)""",
    """(SrcAddress: |src=)"{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """((?i)TargetProcess)"?(:|=)\s{0,100}"{1,20}({process}[^"]+\\({process_name}[^"]+))""",
  ]
  DupFields = ["host->dest_host"]
}
```