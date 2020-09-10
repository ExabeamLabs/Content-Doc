#### Parser Content
```Java
{
Name = perforce-app-activity-1
  Vendor = Perforce
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """Perforce server""", """ info:""" ]
  Fields = [
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d\spid ({pid}\d+) (({user}[^@\s]+)@)?({additional_info}[^\s]+)""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
    """\]\s+'({activity}[^\s\']+)""",
    """\s+({object}\/+[^\/\s'@\.]+(\/+[^\/\s'@\.]+)?)?\s*(|({resource}[^'\s\-]+?))'\s*$""",
    """\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s({activity}[^\[\]']+?)\s\/\/""",
  ]
}
```