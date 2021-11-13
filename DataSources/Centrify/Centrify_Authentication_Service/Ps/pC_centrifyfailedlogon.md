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
    """user=({user}[^\(\)\s@]{1,2000})\(""",
    """user=({user}[^\(\)\s@]{1,2000})@({domain}[^\(\)\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\|({event_name}Trusted path\s{1,100}[^\|]{0,2000})\|""",
    """status=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """pid=({pid}\d{1,100})""",
    """server=(({protocol}[^\\\/\s]{1,2000})[\\\/]{1,2000})?({dest_host}[^\\\/\s]{1,2000}?)\s{1,100}(\w+=|$)""",
    """reason=:?\s{0,100}({failure_reason}.+?)\s{1,100}(\w+=|$)""",
  ]


}
```