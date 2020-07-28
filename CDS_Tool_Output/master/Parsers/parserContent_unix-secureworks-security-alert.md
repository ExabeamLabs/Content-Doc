#### Parser Content
```Java
{
Name = unix-secureworks-security-alert
  Vendor = SecureWorks
  Product = iSensor IPS
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """iSensor: [**]""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """({host}[\w\.-]+)\s+iSensor:""",
    """\[Time:\s+({time}\d+)""",
    """iSensor:\s+(\[.*?\]\s+){2}(?:\d+\s+)?(?:VID\d+\s+)?({alert_name}[^\[]+?)\s+\[""",
    """\[Event ID:\s+({alert_id}\d+)""",
    """\[Priority:\s+({alert_severity}\d+)""",
    """\[src IP:\s+({src_ip}[^\s\]]+)""",
    """\[dst IP:\s+({dest_ip}[^\s\]]+)""",
    """\[EX HTTP_URI 9:\s+({target_uri}.+?)\]\s""",
    """\[EX HTTP_HOSTNAME 10:\s+({target_host}[^\s\]]+)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```