#### Parser Content
```Java
{
Name = syslog-l7-security-alert
  Vendor = Kemp
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """ l7log:""", """ Attempted """, """ attack on """ ]
  Fields = [
    """exabeam_host=({host}[\w\.\-]+)""",
    """\s({host}[\w\.\-]+)\s+\S+\s+\S+\s+l7log:""",
    """attack on\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\s+from\s+({malware_url}[^\(\s]+)\s+\(({additional_info}.+?)\)""",
    """\sAttempted\s+({alert_name}.+?)\s+on""",
  ]
  DupFields = [ alert_name->alert_type ]
}
```