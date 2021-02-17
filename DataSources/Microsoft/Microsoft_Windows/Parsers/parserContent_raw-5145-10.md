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
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+(CEF|dsa_lca):""",
    """({event_name}A network share object was checked to see whether the client can be granted desired access)""",
    """({event_code}5145)""",
    """domain:\s+[^\s:]+:\s+({user_sid}[^\s]+)\s+({user}[^\s]+)\s({domain}[^\s]+)\s+({logon_id}[^\s]+)\s+({file_type}[^\s]+)\s+({src_ip}[A-Fa-f:\d.]+)\s+({src_port}\d+)\s+({share_name}[^\s]+)\s*(({share_path}[^\s]+)\s+({file_path}({file_parent}.*?[\\\/]+)?({file_name}[^\\\/]+?(\.({file_ext}\w+))?)?)\s+({access_mask}0x\d+)\s+({accesses}[^:]+?)\s+({access_reason}[\%\d]+:.+?)\s+)?$"""
  ]
  DupFields = ["host->dest_host"]
}
```