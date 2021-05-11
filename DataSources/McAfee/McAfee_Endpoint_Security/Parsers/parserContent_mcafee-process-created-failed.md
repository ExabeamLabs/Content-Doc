#### Parser Content
```Java
{
Name = mcafee-process-created-failed
  Vendor = McAfee
  Product = McAfee Endpoint Security
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<SCORevent_name>EXECUTION_DENIED""", """EPOEvents""" ]
  Fields = [
    """<GMTTime>({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)</GMTTime>""",
    """exabeam_host=({host}[^\s]+)""",
    """({host}[\w\-.]+)\s{1,100}EPOEvents""",
    """<SCORuser_name>(({domain}[^\\\/<>]+)[\\\/]+)?({user}[^\\\/<>]+)</SCORuser_name>""",
    """<SCORfile_name>({file_path}({file_parent}[^<>]*?[\\\/<>]+)?({file_name}[^\\\/<>]+?(\.({file_ext}\w+))?))</SCORfile_name>""",
    """<SCORprocess_name>({process}({directory}[^<>]*?[\\\/]+)?({process_name}[^\\\/<>]+))</SCORprocess_name>""",
    """<SCORparent_process_name>({parent_process}({parent_directory}[^<>]*?[\\\/]+)?({parent_process_name}[^\\\/<>]+))</SCORparent_process_name>""",
    """<SCORdeny_reason>({failure_reason}.+?)</SCORdeny_reason>""",
    """<SCORfile_type>({file_type}.+?)</SCORfile_type>""",
    """<SCORfile_md5>({md5}.+?)</SCORfile_md5>""",
    """<RawMACAddress>({src_mac}.+?)</RawMACAddress>""",
    """<MachineName>({src_host}.+?)</MachineName>""",
    """<SCORevent_name>({outcome}.+?)</SCORevent_name>""",
    """<IPAddress>({src_ip}.+?)</IPAddress>""",
    """<OSName>({os}.+?)</OSName>""",
  ]
}
```