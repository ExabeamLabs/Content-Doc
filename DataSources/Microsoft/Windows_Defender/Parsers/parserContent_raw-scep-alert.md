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
    """,({time}\w+ \w+ \d{1,100} \d\d:\d\d:\d\d \d{1,100}),""",
    """exabeam_source=({host}[\w.\-]+)""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
    """(?:([^",]*,)){7}({src_host}[^,\.]+)""",
    """ComputerName=({src_host}[\w.\-]+)""",
    """\s{1,100}Name:\s{1,100}({alert_name}.+?)\s{1,100}ID:""",
    """\s{1,100}ID:\s{1,100}({alert_id}\d{1,100})""",
    """\s{1,100}Severity:\s{1,100}({alert_severity}.+?)\s{1,100}Category""",
    """\s{1,100}Category:\s{1,100}({alert_type}.+?)\s{1,100}Path:""",
    """\s{1,100}Path:\s{1,100}({malware_url}.+?)(;|\s{1,100}Detection Origin)""",
    """\s{1,100}User:\s{1,100}({user}.+?)\s{1,100}Process Name:""",
    """C:\\Users\\({user}[^\\]+)"""
  ]
}
```