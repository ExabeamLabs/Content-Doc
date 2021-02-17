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
    """What\s*:\s*(.+?\\+)?({database_name}[^\s]+)""",
    """Who\s*:\s*(({domain}[^\s]+)\\+)?(system|({user}[^\s]+))"""
    """Where\s*:\s*({dest_host}[\w\-.]+)""",
    """Workstation\s*:\s*(|({src_ip}[A-Fa-f:\d.]+))\s*Details\s*:""",
    """ObjectType\s*:\s*({additional_info}.+?)\s*\w+\s*:\s*""",
    """Device name:\s*"*({service_name}[^",\s]+)""",
    """Message\s*:\s*({reason}.+?)\s*\w+\s*:"""
    """DataSource\s*:\s*({app}.+?)\s*\w+\s*:"""
    """Application name:\s*({app}.+?)\s*$"""
  ]
}
```