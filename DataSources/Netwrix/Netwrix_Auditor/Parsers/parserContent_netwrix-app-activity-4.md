#### Parser Content
```Java
{
Name = netwrix-app-activity-4
   Vendor = Netwrix
  Product = Netwrix Auditor
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = ["""DataSource : VMware""" , """Action :""", """Where :""" , """Who :"""]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w.\-]+)""",
    """When\s{0,100}:\s{0,100}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """\sMessage:\s{0,100}({activity}[^:]+?)\s{0,100}\w+\s{0,100}:""",
    """Who\s{0,100}:\s{0,100}(({domain}[^\\\s]+)\\+)?(system|({user}[^\\\s]+))""",
    """Where\s{0,100}:\s{0,100}(\w+:\/+)({dest_host}[\w\-.]+)""",
    """ObjectType\s{0,100}:\s{0,100}({additional_info}.+?)\s{0,100}\w+\s{0,100}:""",
    """What\s{0,100}:\s{0,100}({resource}.+?)({object}[^\\]+?)\s{1,100}When\s{0,100}:""",
    """({app}VMware)""",
  ]
}
```