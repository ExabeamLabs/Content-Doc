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
    """exabeam_host=({host}[\w.\-]+)""",
    """\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d\s({user}[^@]+)""",
    """\d\d:\d\d:\d\d\s[^@]+@({additional_info}[^\s]+)""",
    """\s({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/""",
    """\/({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
    """\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s({activity}.+?)\s\/\/""",
    """\s({object}\/\/[^\/]+\/[^\/]+)""",
    """\s\/\/([^\/]+\/){2}({resource}.+?)$"""
  ]
}
```