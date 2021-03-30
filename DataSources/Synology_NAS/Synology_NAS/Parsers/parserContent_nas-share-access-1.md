#### Parser Content
```Java
{
Name = nas-share-access-1
  Vendor = Synology NAS
  Product = Synology NAS
  Lms = Direct
  DataType = "share-access"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """ Connection """, """accessed the shared folder""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """>\w+ \d\d \d\d:\d\d:\d\d\s+({host}\S+)""",
    """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """Connection\s+(({domain}[^\\]+)\\)?({user}[^\\,]+),""",
    """({protocol}\S+)\s+client\s+\[(({domain}[^\\]+)\\)?({user}[^\\]+?)\]""",
    """from .*?IP:({src_ip}[a-fA-F\d.:]+)""",
    """accessed the shared ({file_type}folder) \[({share_name}.+?)\]"""
  ]
}
```