#### Parser Content
```Java
{
Name = centrify-failed-logon
  Vendor = Centrify
  Product = Centrify
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "epoch"
  Conditions = ["""|Centrify Suite|Trusted Path|""" , """|Trusted path denied|"""]
  Fields = [
    """utc=({time}\d+)""",
    """user=({user}[^\(\)\s@]+)\(""",
    """user=({user}[^\(\)\s@]+)@({domain}[^\(\)\s@]+)\s+(\w+=|$)""",
    """\|({event_name}Trusted path\s+[^\|]*)\|""",
    """status=({outcome}.+?)\s+(\w+=|$)""",
    """pid=({pid}\d+)""",
    """server=(({protocol}[^\\\/\s]+)[\\\/]+)?({dest_host}[^\\\/\s]+?)\s+(\w+=|$)""",
    """reason=:?\s*({failure_reason}.+?)\s+(\w+=|$)""",
  ]
}
```