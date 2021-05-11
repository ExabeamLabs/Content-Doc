#### Parser Content
```Java
{
Name = f5-vpn-assign-ip
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-set-ip"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ 01490549:5:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d\s{1,100}({host}[^\s]+)\s([^\s]+\s)?[^\s]+\[\d{1,100}\]""",
    """\s{1,100}01490549:5:.*?({session_id}[^\s:]+): Assigned """,
    """IPv4:\s{1,100}({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sClient IP:\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```