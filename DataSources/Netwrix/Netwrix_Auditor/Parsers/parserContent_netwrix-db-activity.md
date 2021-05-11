#### Parser Content
```Java
{
Name = netwrix-db-activity
   Vendor = Netwrix
  Product = Netwrix Auditor
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = ["""DataSource : SQL""" , """Where :""" , """Who :"""]
  Fields = [
    """When : ({time}[^\s]+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """What\s{0,100}:\s{0,100}(.+?\\+)?({database_name}[^\s]+)""",
    """Who\s{0,100}:\s{0,100}(({domain}[^\s]+)\\+)?(system|({user}[^\s]+))"""
    """Where\s{0,100}:\s{0,100}({dest_host}[\w\-.]+)""",
    """Workstation\s{0,100}:\s{0,100}(|({src_ip}[A-Fa-f:\d.]+))\s{0,100}Details\s{0,100}:""",
    """ObjectType\s{0,100}:\s{0,100}({additional_info}.+?)\s{0,100}\w+\s{0,100}:\s{0,100}""",
    """Device name:\s{0,100}"{0,20}({service_name}[^",\s]+)""",
    """Message\s{0,100}:\s{0,100}({reason}.+?)\s{0,100}\w+\s{0,100}:"""
    """DataSource\s{0,100}:\s{0,100}({app}.+?)\s{0,100}\w+\s{0,100}:"""
    """Application name:\s{0,100}({app}.+?)\s{0,100}$"""
  ]
}
```