#### Parser Content
```Java
{
Name = f5-vpn-assign-ip
  Vendor = F5
  Product = Big-IP
  Lms = Splunk
  DataType = "vpn-set-ip"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ 01490549:5:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d\s+({host}[^\s]+)\s([^\s]+\s)?[^\s]+\[\d+\]""",
    """\s+01490549:5:.*?({session_id}[^\s:]+): Assigned """,
    """IPv4:\s+({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sClient IP:\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```