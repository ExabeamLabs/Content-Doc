#### Parser Content
```Java
{
Name = nas-share-access
  Vendor = Synology NAS
  Product = Synology NAS
  Lms = Direct
  DataType = "share-access"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """ WinFileService Event:""", """, File/Folder:""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """>\w+ \d\d \d\d:\d\d:\d\d\s{1,100}({host}\S+)""",
    """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """Event:\s{0,100}({accesses}[^,]{1,2000}),""",
    """Path:\s{0,100}({file_path}({file_parent}[^,]{0,2000}?)[\\\/]{0,2000}({file_name}[^,\\\/]{1,2000}?)),""",
    """Path:\s{0,100}\/({share_name}[^\/]{1,2000})""",
    """File\/Folder:\s{0,100}({file_type}[^,]{1,2000}?),""",
    """Size:\s{0,100}({bytes_num}[\d\.]{1,2000})\s{1,100}({bytes_unit}\w+),""",
    """User:\s{0,100}(({domain}[^\\]{1,2000})\\)?({user}[^\\,]{1,2000}),""",
    """IP:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})"""
  ]
}
```