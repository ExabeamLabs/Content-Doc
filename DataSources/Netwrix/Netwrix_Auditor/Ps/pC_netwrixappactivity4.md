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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """When\s{0,100}:\s{0,100}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """\sMessage:\s{0,100}({activity}[^:]{1,2000}?)\s{0,100}\w+\s{0,100}:""",
    """Who\s{0,100}:\s{0,100}(({domain}[^\\\s]{1,2000})\\+)?(system|({user}[^\\\s]{1,2000}))""",
    """Where\s{0,100}:\s{0,100}(\w+:\/+)({dest_host}[\w\-.]{1,2000})""",
    """ObjectType\s{0,100}:\s{0,100}({additional_info}.+?)\s{0,100}\w+\s{0,100}:""",
    """What\s{0,100}:\s{0,100}({resource}.+?)({object}[^\\]{1,2000}?)\s{1,100}When\s{0,100}:""",
    """({app}VMware)""",
  ]
}
```