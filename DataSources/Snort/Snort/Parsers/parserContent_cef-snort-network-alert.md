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
    """:\d\d:\d\d\s({host}[\w\-.]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){3}\d{1,100}\.\d{1,100}:\d{1,100}:({alert_id}\d{1,100})""",
    """CEF:([^\|]{0,2000}\|){4}({alert_name}[^|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({alert_severity}\d{1,100})""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """spt=({src_port}\d{1,100})""",
    """dpt=({dest_port}\d{1,100})""",
    """proto=({protocol}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```