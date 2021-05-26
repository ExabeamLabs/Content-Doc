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
    """When : ({time}[^\s]{1,2000})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """What\s{0,100}:\s{0,100}(.+?\\+)?({database_name}[^\s]{1,2000})""",
    """Who\s{0,100}:\s{0,100}(({domain}[^\s]{1,2000})\\+)?(system|({user}[^\s]{1,2000}))"""
    """Where\s{0,100}:\s{0,100}({dest_host}[\w\-.]{1,2000})""",
    """Workstation\s{0,100}:\s{0,100}(|({src_ip}[A-Fa-f:\d.]{1,2000}))\s{0,100}Details\s{0,100}:""",
    """ObjectType\s{0,100}:\s{0,100}({additional_info}.+?)\s{0,100}\w+\s{0,100}:\s{0,100}""",
    """Device name:\s{0,100}"{0,20}({service_name}[^",\s]{1,2000})""",
    """Message\s{0,100}:\s{0,100}({reason}.+?)\s{0,100}\w+\s{0,100}:"""
    """DataSource\s{0,100}:\s{0,100}({app}.+?)\s{0,100}\w+\s{0,100}:"""
    """Application name:\s{0,100}({app}.+?)\s{0,100}$"""
  ]
}
```