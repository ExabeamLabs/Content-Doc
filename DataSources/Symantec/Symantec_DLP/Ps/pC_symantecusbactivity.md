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
    """Message\s{0,100}=\s{0,100}The user\s{0,100} (?:[^\\]{1,2000}\\)?({user}[^\s]{1,2000})\s{0,100}has""",
    """\d\d:\d\d:\dd\s{0,100}({host}[^\s]{1,2000})""",
    """\s{0,100}Endpoint Name:\s{0,100}({dest_host}[^\s]{1,2000})""",
    """\s{0,100}Endpoint IP:\s{0,100}\(({dest_ip}[^\)]{1,2000})""",
    """\s{0,100}filename:\s{0,100}({file_name}[^,]{1,2000})""",
    """\s{0,100}dir:\s{0,100}({file_parent}.+?)\s{0,100}Device Instance ID:""",
    """\s{0,100}Device Instance ID:\s{0,100}({device_id}.+?)\s{1,100}(\w+=|$)""",
    """\s{0,100}Policy Violated:\s{0,100}({alert_name}.+?),\s{0,100}Date""",
    """\s{0,100}Protocol:\s{0,100}({alert_type}.+?),\s{0,100}Count""",
    """incident ID:\s{0,100}({alert_id}\d{1,100})""",
    """Blocked:\s{0,100}({outcome}.+?)\s{0,100}Device Instance ID:"""
  ]
}
```