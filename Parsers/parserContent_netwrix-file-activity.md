#### Parser Content
```Java
{
Name = netwrix-file-activity
  Vendor = Netwrix
  Product = Netwrix Auditor
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """<EventRecordID>""", """ Action : """, """ ObjectType : """, """ What : """ ]
  Fields = [
    """When\s*:\s*({time}\d+-\d+-\d+T\d+:\d+:\d+Z)""",
    """<Computer>({host}[\w\-.]+)""",
    """>({event_code}\d+)<\/EventID>""",
    """<EventRecordID>({record_id}.+?)<\/EventRecordID>""",
    """Action\s*:\s*({accesses}.+?)\s*Message\s*:""",
    """Where\s*:\s*({dest_host}[\w\-.]+)""",
    """ObjectType\s*:\s*({file_type}.+?)\s*Who\s*:""",
    """Who\s*:\s*(({domain}[^\\\s]+)\\+)?(system|({user}[^\\\s]+))""",
    """What\s*:\s*(|({file_path}({file_parent}[^"]*?)[\\\/]*({file_name}[^\\"]+?(\.({file_ext}[^\\\.\s"]+))?)))\s*When\s*:""",
    """Workstation\s*:\s*(|({src_ip}[A-Fa-f:\d.]+))\s*Details\s*:""",
  ]
}
```