#### Parser Content
```Java
{
Name = raw-5145-10
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "share-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""A network share object was checked to see whether the client can be granted desired access""", """(5145)""", """domain:"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s{1,100}(CEF|dsa_lca):""",
    """({event_name}A network share object was checked to see whether the client can be granted desired access)""",
    """({event_code}5145)""",
    """domain:\s{1,100}[^\s:]+:\s{1,100}({user_sid}[^\s]+)\s{1,100}({user}[^\s]+)\s({domain}[^\s]+)\s{1,100}({logon_id}[^\s]+)\s{1,100}({file_type}[^\s]+)\s{1,100}({src_ip}[A-Fa-f:\d.]+)\s{1,100}({src_port}\d{1,100})\s{1,100}({share_name}[^\s]+)\s{0,100}(({share_path}[^\s]+)\s{1,100}({file_path}({file_parent}.*?[\\\/]+)?({file_name}[^\\\/]+?(\.({file_ext}\w+))?)?)\s{1,100}({access_mask}0x\d{1,100})\s{1,100}({accesses}[^:]+?)\s{1,100}({access_reason}[\%\d]+:.+?)\s{1,100})?$"""
  ]
  DupFields = ["host->dest_host"]
}
```