#### Parser Content
```Java
{
Name = centrify-failed-logon
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "epoch"
  Conditions = ["""|Centrify Suite|Trusted Path|""" , """|Trusted path denied|"""]
  Fields = [
    """utc=({time}\d{1,100})""",
    """user=({user}[^\(\)\s@]+)\(""",
    """user=({user}[^\(\)\s@]+)@({domain}[^\(\)\s@]+)\s{1,100}(\w+=|$)""",
    """\|({event_name}Trusted path\s{1,100}[^\|]*)\|""",
    """status=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """pid=({pid}\d{1,100})""",
    """server=(({protocol}[^\\\/\s]+)[\\\/]+)?({dest_host}[^\\\/\s]+?)\s{1,100}(\w+=|$)""",
    """reason=:?\s{0,100}({failure_reason}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```