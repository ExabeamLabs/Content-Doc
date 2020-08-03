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
    """>\w+ \d\d \d\d:\d\d:\d\d\s+({host}\S+)""",
    """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """Event:\s*({accesses}[^,]+),""",
    """Path:\s*({file_path}({file_parent}[^,]*?)[\\\/]*({file_name}[^,\\\/]+?)),""",
    """Path:\s*\/({share_name}[^\/]+)""",
    """File\/Folder:\s*({file_type}[^,]+?),""",
    """Size:\s*({bytes_num}[\d\.]+)\s+({bytes_unit}\w+),""",
    """User:\s*(({domain}[^\\]+)\\)?({user}[^\\,]+),""",
    """IP:\s*({src_ip}[a-fA-F\d.:]+)"""
  ]
}
```