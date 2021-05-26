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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d\spid ({pid}\d{1,100}) (({user}[^@\s]{1,2000})@)?({additional_info}[^\s]{1,2000})""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
    """\]\s{1,100}'({activity}[^\s\']{1,2000})""",
    """\s{1,100}({object}\/+[^\/\s'@\.]{1,2000}(\/+[^\/\s'@\.]{1,2000})?)?\s{0,100}(|({resource}[^'\s\-]{1,2000}?))'\s{0,100}$""",
    """\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s({activity}[^\[\]']{1,2000}?)\s\/\/""",
  ]
}
```