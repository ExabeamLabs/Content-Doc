#### Parser Content
```Java
{
Name = perforce-app-activity
  Vendor = Perforce
  Product = Perforce
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """<Perforce Condition>""" ]
  Fields = [
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d\s({user}[^@]{1,2000})""",
    """\d\d:\d\d:\d\d\s[^@]{1,2000}@({additional_info}[^\s]{1,2000})""",
    """\s({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/""",
    """\/({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
    """\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s({activity}.+?)\s\/\/""",
    """\s({object}\/\/[^\/]{1,2000}\/[^\/]{1,2000})""",
    """\s\/\/([^\/]{1,2000}\/){2}({resource}.+?)$"""
  ]
}
```