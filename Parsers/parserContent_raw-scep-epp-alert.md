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
    """exabeam_host=(\S+@\s*)?({host}[^\s]+)""",
    """\sdest_name="+({src_host}[^\s"]+)""",
    """(Timestamp: |Timestamp=)"+({time}\d+-\d+-\d+ \d\d:\d\d:\d\d)""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """((?i)RowID)"?:\s*"+({alert_id}[^"]+)""",
    """((?i)TargetHost)"?:\s*"+({dest_host}[^"]+)""",
    """((?i)TargetUser"?:\s*|user=)"+(({domain}[^\\]+)\\+)?({user}[^"\\]+)""",
    """((?i)TargetResource)"?:\s*"+({additional_info}[^"]+)""",
    """((?i)ClassificationType"?:\s*|signature=)"+({alert_name}[^"]+)""",
    """((?i)ClassificationSeverity"?:\s*|severity=)"+({alert_severity}[^"]+)""",
    """((?i)ClassificationCategory"?:\s*|category=)"+({alert_type}[^"]+)""",
    """\sfile_path="+({malware_url}[^",]+)""",
    """(SrcAddress: |src=)"+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```