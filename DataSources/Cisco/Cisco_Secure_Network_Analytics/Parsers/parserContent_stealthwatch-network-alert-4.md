#### Parser Content
```Java
{
Name = stealthwatch-network-alert-4
  Vendor = Cisco
  Product = Cisco Secure Network Analytics
  Lms = Syslog
  DataType = "network-alert"
  TimeFormat =  "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """Cisco|Stealthwatch""", """src""", """externalId""", """dvchost""" ]
  Fields = [
    """dvchost=({host}[^\s]+)""",
    """start=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """src=({src_ip}[a-fA-F0-9.:]+)""",
    """dst=(0.0.0.0|({dest_ip}[a-fA-F0-9.:]+))""",
    """msg=({additional_info}[^=]+)\s+""",
    """externalId=({alert_id}[^\s]+)""",
    """dvc=({host_ip}[a-fA-F0-9.:]+)""",
    """CEF:([^\|]+\|){4}({event_code}[^\|]+)""",
    """CEF:([^\|]+\|){6}({alert_severity}[^\|]+)""",
    """CEF:([^\|]+\|){5}({alert_name}[^\|]+)""",
  ]
  DupFields = [ "alert_name->alert_type", "alert_name->event_name"]
}
```