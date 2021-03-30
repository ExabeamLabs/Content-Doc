#### Parser Content
```Java
{
Name = raw-scep-alert
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Direct
  DataType = "alert"
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy"
  Conditions = [ "Microsoft Antimalware", "Detection Origin" ]
  Fields = [
    """,({time}\w+ \w+ \d+ \d\d:\d\d:\d\d \d+),""",
    """exabeam_source=({host}[\w.\-]+)""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """(?:([^",]*,)){7}({src_host}[^,\.]+)""",
    """ComputerName=({src_host}[\w.\-]+)""",
    """\s+Name:\s+({alert_name}.+?)\s+ID:""",
    """\s+ID:\s+({alert_id}\d+)""",
    """\s+Severity:\s+({alert_severity}.+?)\s+Category""",
    """\s+Category:\s+({alert_type}.+?)\s+Path:""",
    """\s+Path:\s+({malware_url}.+?)(;|\s+Detection Origin)""",
    """\s+User:\s+({user}.+?)\s+Process Name:""",
    """C:\\Users\\({user}[^\\]+)"""
  ]
}
```