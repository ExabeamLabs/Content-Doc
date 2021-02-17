#### Parser Content
```Java
{
Name = centrify-local-logon
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Direct
  DataType = "local-logon"
  TimeFormat = "epoch"
  Conditions = ["""|Centrify Suite|Trusted Path|""" , """|Trusted path granted|"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """utc=({time}\d+)""",
    """user=({user}[^\(\)\s@]+)\(""",
    """user=({user}[^\(\)\s@]+)@({domain}[^\(\)\s@]+)\s+(\w+=|$)""",
    """\|({event_name}Trusted path\s+[^\|]*)\|""",
    """status=({outcome}.+?)\s+(\w+=|$)""",
    """pid=({pid}\d+)""",
    """server=(({protocol}[^\\\/\s]+)[\\\/]+)?({dest_host}[^\\\/\s]+?)\s+(\w+=|$)""",
  ]
}
```