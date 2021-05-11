#### Parser Content
```Java
{
Name = perforce-app-activity-1
  Vendor = Perforce
  Product = Perforce
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """Perforce server""", """ info:""" ]
  Fields = [
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d\spid ({pid}\d{1,100}) (({user}[^@\s]+)@)?({additional_info}[^\s]+)""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
    """\]\s{1,100}'({activity}[^\s\']+)""",
    """\s{1,100}({object}\/+[^\/\s'@\.]+(\/+[^\/\s'@\.]+)?)?\s{0,100}(|({resource}[^'\s\-]+?))'\s{0,100}$""",
    """\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s({activity}[^\[\]']+?)\s\/\/""",
  ]
}
```