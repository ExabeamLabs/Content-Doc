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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """utc=({time}\d{1,100})""",
    """user=({user}[^\(\)\s@]+)\(""",
    """user=({user}[^\(\)\s@]+)@({domain}[^\(\)\s@]+)\s{1,100}(\w+=|$)""",
    """\|({event_name}Trusted path\s{1,100}[^\|]*)\|""",
    """status=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """pid=({pid}\d{1,100})""",
    """server=(({protocol}[^\\\/\s]+)[\\\/]+)?({dest_host}[^\\\/\s]+?)\s{1,100}(\w+=|$)""",
  ]
}
```