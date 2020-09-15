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
    """exabeam_host=({host}[^\s]+)""",
    """({host}[\w\-.]+)\s+EPOEvents""",
    """<SCORuser_name>(({domain}[^\\\/<>]+)[\\\/]+)?({user}[^\\\/<>]+)</SCORuser_name>""",
    """<SCORfile_name>({file_path}({file_parent}[^<>]*?[\\\/<>]+)?({file_name}[^\\\/<>]+?(\.({file_ext}\w+))?))</SCORfile_name>""",
    """<SCORprocess_name>({process}({directory}[^<>]*?[\\\/]+)?({process_name}[^\\\/<>]+))</SCORprocess_name>""",
    """<RawMACAddress>({src_mac}.+?)</RawMACAddress>""",
    """<MachineName>({src_host}.+?)</MachineName>""",
    """<SCORevent_name>({outcome}.+?)</SCORevent_name>""",
    """<IPAddress>({src_ip}.+?)</IPAddress>""",
    """<OSName>({os}.+?)</OSName>""",
  ]
}
```