#### Parser Content
```Java
{
Name = stealthwatch-network-alert-3
  Vendor = Cisco
  Product = Cisco Secure Network Analytics
  Lms = Syslog
  DataType = "network-alert"
  TimeFormat =  "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """cisco|stealthwatch""", """category=""", """fc_dvc_ip=""", """fc_dvc=""" ]
  Fields = [
    """"timestamp":"({time}\d\d\d\d-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """fc_dvc=({host}[^\s]{1,2000})""",
    """CEF:([^\|]{1,2000}\|){2}({alert_name}[^\|]{1,2000})""",
    """CEF:([^\|]{1,2000}\|){5}({event_name}[^\|]{1,2000})""",
    """CEF:([^\|]{1,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
    """category=({alert_type}[^=]{1,2000}?)\s{1,100}\w+=""",
    """message=({additional_info}[^=]{1,2000})\s{1,100}\w+=""",
    """src_ip=({src_ip}[a-fA-F\d:\.]{1,2000})""",
    """dest_ip=(0\.0\.0\.0|({dest_ip}[a-fA-F\d:\.]{1,2000}))""",
    """src=({src_host}[^\s]{1,2000})""",
    """src_user=({user}[^\s]{1,2000})""",
    """dest=({dest_host}[^\s]{1,2000})""",
    """dest_port=({dest_port}\d{1,100})"""
  ]


}
```