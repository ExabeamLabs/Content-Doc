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
    """'PaSeries @ ({src_host}[^\s']{1,2000})( \(({src_ip}[^\)]{1,2000})\))?'"""
    """({alert_name}A device has stopped emitting events)"""
  ]
}
```