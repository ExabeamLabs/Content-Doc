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
    """exabeam_host=({host}[\w.\-]+)""",
    """>\w+ \d\d \d\d:\d\d:\d\d\s{1,100}({host}\S+)""",
    """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """Event:\s{0,100}({accesses}[^,]+),""",
    """Path:\s{0,100}({file_path}({file_parent}[^,]*?)[\\\/]*({file_name}[^,\\\/]+?)),""",
    """Path:\s{0,100}\/({share_name}[^\/]+)""",
    """File\/Folder:\s{0,100}({file_type}[^,]+?),""",
    """Size:\s{0,100}({bytes_num}[\d\.]+)\s{1,100}({bytes_unit}\w+),""",
    """User:\s{0,100}(({domain}[^\\]+)\\)?({user}[^\\,]+),""",
    """IP:\s{0,100}({src_ip}[a-fA-F\d.:]+)"""
  ]
}
```