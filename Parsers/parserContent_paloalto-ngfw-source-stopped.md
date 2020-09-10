#### Parser Content
```Java
{
Name = paloalto-ngfw-source-stopped
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "network-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""A device has stopped emitting events""", """'PaSeries @"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """'PaSeries @ ({src_host}[^\s']+)( \(({src_ip}[^\)]+)\))?'"""
    """({alert_name}A device has stopped emitting events)"""
  ]
}
```