#### Parser Content
```Java
{
Name = symantec-usb-activity
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Endpoint Name:""","""Endpoint Server:""", """Policy Violated:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Message\s*=\s*The user\s* (?:[^\\]+\\)?({user}[^\s]+)\s*has""",
    """\d\d:\d\d:\dd\s*({host}[^\s]+)""",
    """\s*Endpoint Name:\s*({dest_host}[^\s]+)""",
    """\s*Endpoint IP:\s*\(({dest_ip}[^\)]+)""",
    """\s*filename:\s*({file_name}[^,]+)""",
    """\s*dir:\s*({file_parent}.+?)\s*Device Instance ID:""",
    """\s*Device Instance ID:\s*({device_id}.+?)\s+(\w+=|$)""",
    """\s*Policy Violated:\s*({alert_name}.+?),\s*Date""",
    """\s*Protocol:\s*({alert_type}.+?),\s*Count""",
    """incident ID:\s*({alert_id}\d+)""",
    """Blocked:\s*({outcome}.+?)\s*Device Instance ID:"""
  ]
}
```