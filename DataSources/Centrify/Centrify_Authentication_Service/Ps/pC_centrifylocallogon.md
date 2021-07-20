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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """utc=({time}\d{1,100})""",
    """user=({user}[^\(\)\s@]{1,2000})\(""",
    """user=({user}[^\(\)\s@]{1,2000})@({domain}[^\(\)\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\|({event_name}Trusted path\s{1,100}[^\|]{0,2000})\|""",
    """status=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """pid=({pid}\d{1,100})""",
    """server=(({protocol}[^\\\/\s]{1,2000})[\\\/]{1,2000})?({dest_host}[^\\\/\s]{1,2000}?)\s{1,100}(\w+=|$)""",
  ]
}
```