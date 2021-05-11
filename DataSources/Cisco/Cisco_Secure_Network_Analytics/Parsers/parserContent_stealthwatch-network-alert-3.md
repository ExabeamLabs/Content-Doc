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
    """fc_dvc=({host}[^\s]+)""",
    """CEF:([^\|]+\|){2}({alert_name}[^\|]+)""",
    """CEF:([^\|]+\|){5}({event_name}[^\|]+)""",
    """CEF:([^\|]+\|){6}({alert_severity}[^\|]+)""",
    """category=({alert_type}[^=]+?)\s{1,100}\w+=""",
    """message=({additional_info}[^=]+)\s{1,100}\w+=""",
    """src_ip=({src_ip}[a-fA-F\d:\.]+)""",
    """dest_ip=(0\.0\.0\.0|({dest_ip}[a-fA-F\d:\.]+))""",
    """src=({src_host}[^\s]+)""",
    """src_user=({user}[^\s]+)""",
    """dest=({dest_host}[^\s]+)""",
    """dest_port=({dest_port}\d{1,100})"""
  ]
}
```