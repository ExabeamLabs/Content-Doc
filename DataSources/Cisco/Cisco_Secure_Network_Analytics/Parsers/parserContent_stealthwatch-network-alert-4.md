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
    """dvchost=({host}[^\s]{1,2000})""",
    """start=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """src=({src_ip}[a-fA-F0-9.:]{1,2000})""",
    """dst=(0.0.0.0|({dest_ip}[a-fA-F0-9.:]{1,2000}))""",
    """msg=({additional_info}[^=]{1,2000})\s{1,100}""",
    """externalId=({alert_id}[^\s]{1,2000})""",
    """dvc=({host_ip}[a-fA-F0-9.:]{1,2000})""",
    """CEF:([^\|]{1,2000}\|){4}({event_code}[^\|]{1,2000})""",
    """CEF:([^\|]{1,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
    """CEF:([^\|]{1,2000}\|){5}({alert_name}[^\|]{1,2000})""",
  ]
  DupFields = [ "alert_name->alert_type", "alert_name->event_name"]
}
```