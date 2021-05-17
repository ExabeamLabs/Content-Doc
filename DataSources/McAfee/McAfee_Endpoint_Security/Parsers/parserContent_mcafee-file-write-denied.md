#### Parser Content
```Java
{
Name = mcafee-file-write-denied
  Vendor = McAfee
  Product = McAfee Endpoint Security
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<SCORevent_name>WRITE_DENIED""", """EPOEvents""" ]
  Fields = [
    """<GMTTime>({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)</GMTTime>""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({host}[\w\-.]{1,2000})\s{1,100}EPOEvents""",
    """<SCORuser_name>(({domain}[^\\\/<>]{1,2000})[\\\/]{1,2000})?({user}[^\\\/<>]{1,2000})</SCORuser_name>""",
    """<SCORfile_name>({file_path}({file_parent}[^<>]{0,2000}?[\\\/<>]{1,2000})?({file_name}[^\\\/<>]{1,2000}?(\.({file_ext}\w+))?))</SCORfile_name>""",
    """<SCORprocess_name>({process}({directory}[^<>]{0,2000}?[\\\/]{1,2000})?({process_name}[^\\\/<>]{1,2000}))</SCORprocess_name>""",
    """<RawMACAddress>({src_mac}.+?)</RawMACAddress>""",
    """<MachineName>({src_host}.+?)</MachineName>""",
    """<SCORevent_name>({outcome}.+?)</SCORevent_name>""",
    """<IPAddress>({src_ip}.+?)</IPAddress>""",
    """<OSName>({os}.+?)</OSName>""",
  ]
}
```