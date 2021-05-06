#### Parser Content
```Java
{
Name = cef-snort-network-alert
  Vendor = Snort
  Product = Snort
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|snort|""", """proto=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """:\d\d:\d\d\s({host}[\w\-.]+)""",
    """CEF:([^\|]*\|){3}\d+\.\d+:\d+:({alert_id}\d+)""",
    """CEF:([^\|]*\|){4}({alert_name}[^|]+)""",
    """CEF:([^\|]*\|){5}({alert_severity}\d+)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """spt=({src_port}\d+)""",
    """dpt=({dest_port}\d+)""",
    """proto=({protocol}[^=]+?)\s*(\w+=|$)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```