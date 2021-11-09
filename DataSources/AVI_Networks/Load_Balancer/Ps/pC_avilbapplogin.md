#### Parser Content
```Java
{
Name = avi-lb-app-login
  Vendor = AVI Networks
  Product = Load Balancer
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Avi-Controller:""", """event USER_LOGIN occurred""", """login (Success) from""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """At\s({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """User\s({user}[^\s]{1,2000})""",
    """from\s({src_ip}[a-fA-F\d\.:]{1,2000})""",
    """event\s({event_name}USER_LOGIN)""",
    """login\s\(({outcome}Success)\)""",
    """object\s({object}[^\s]{1,2000})""",
  ]
}
}
```