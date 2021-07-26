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
    """When\s{0,100}:\s{0,100}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """<Computer>({host}[\w\-.]{1,2000})""",
    """>({event_code}\d{1,100})<\/EventID>""",
    """<EventRecordID>({record_id}.+?)<\/EventRecordID>""",
    """Action\s{0,100}:\s{0,100}({accesses}.+?)\s{0,100}Message\s{0,100}:""",
    """Where\s{0,100}:\s{0,100}({dest_host}[\w\-.]{1,2000})""",
    """ObjectType\s{0,100}:\s{0,100}({file_type}.+?)\s{0,100}Who\s{0,100}:""",
    """Who\s{0,100}:\s{0,100}(({domain}[^\\\s]{1,2000})\\+)?(system|({user}[^\\\s]{1,2000}))""",
    """What\s{0,100}:\s{0,100}(|({file_path}({file_parent}[^"]{0,2000}?)[\\\/]{0,2000}({file_name}[^\\"]{1,2000}?(\.({file_ext}[^\\\.\s"]{1,2000}))?)))\s{0,100}When\s{0,100}:""",
    """Workstation\s{0,100}:\s{0,100}(|({src_ip}[A-Fa-f:\d.]{1,2000}))\s{0,100}Details\s{0,100}:""",
  ]
}
```