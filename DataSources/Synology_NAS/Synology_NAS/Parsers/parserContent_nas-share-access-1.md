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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """>\w+ \d\d \d\d:\d\d:\d\d\s{1,100}({host}\S+)""",
    """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """Connection\s{1,100}(({domain}[^\\]{1,2000})\\)?({user}[^\\,]{1,2000}),""",
    """({protocol}\S+)\s{1,100}client\s{1,100}\[(({domain}[^\\]{1,2000})\\)?({user}[^\\]{1,2000}?)\]""",
    """from .*?IP:({src_ip}[a-fA-F\d.:]{1,2000})""",
    """accessed the shared ({file_type}folder) \[({share_name}.+?)\]"""
  ]
}
```