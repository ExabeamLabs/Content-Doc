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
    """({host}[\w\.-]+)\s{1,100}iSensor:""",
    """\[Time:\s{1,100}({time}\d{1,100})""",
    """iSensor:\s{1,100}(\[.*?\]\s{1,100}){2}(?:\d{1,100}\s{1,100})?(?:VID\d{1,100}\s{1,100})?({alert_name}[^\[]+?)\s{1,100}\[""",
    """\[Event ID:\s{1,100}({alert_id}\d{1,100})""",
    """\[Priority:\s{1,100}({alert_severity}\d{1,100})""",
    """\[src IP:\s{1,100}({src_ip}[^\s\]]+)""",
    """\[dst IP:\s{1,100}({dest_ip}[^\s\]]+)""",
    """\[EX HTTP_URI 9:\s{1,100}({target_uri}.+?)\]\s""",
    """\[EX HTTP_HOSTNAME 10:\s{1,100}({target_host}[^\s\]]+)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```