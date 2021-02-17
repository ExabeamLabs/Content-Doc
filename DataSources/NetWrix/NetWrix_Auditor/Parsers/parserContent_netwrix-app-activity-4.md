#### Parser Content
```Java
{
Name = netwrix-app-activity-4
   Vendor = NetWrix
  Product = NetWrix Auditor
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = ["""DataSource : VMware""" , """Action :""", """Where :""" , """Who :"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w.\-]+)""",
    """When\s*:\s*({time}\d+-\d+-\d+T\d+:\d+:\d+Z)""",
    """\sMessage:\s*({activity}[^:]+?)\s*\w+\s*:""",
    """Who\s*:\s*(({domain}[^\\\s]+)\\+)?(system|({user}[^\\\s]+))""",
    """Where\s*:\s*(\w+:\/+)({dest_host}[\w\-.]+)""",
    """ObjectType\s*:\s*({additional_info}.+?)\s*\w+\s*:""",
    """What\s*:\s*({resource}.+?)({object}[^\\]+?)\s+When\s*:""",
    """({app}VMware)""",
  ]
}
```