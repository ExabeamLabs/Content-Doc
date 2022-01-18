#### Parser Content
```Java
{
Name = sysmon-file-delete
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """File Delete:""", """IMPHASH=""", """User:""" ]
  Fields = [
    """exabeam_host=([^=@]{1,2000}@\s{0,100})?({host}\S+)""",
    """({event_name}File Delete)""",
    """\s({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)\s""",
    """ProcessGuid:\s\{({process_guid}[^\}]{1,2000})\}""",
    """ProcessId:\s({pid}\d{1,100})""",
    """User:\s(NT|[^\\]{1,2000}\\({user}[^\s]{1,2000}))""",
    """Image:\s{1,100}({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^\s]{1,2000}))\s{1,100}\w+:""",
    """TargetFilename:\s({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?))\s{1,100}\w+:""",
    """MD5=({md5}[^,]{1,2000}),""",
    """SHA256=({sha256}[^,]{1,2000}),""",
  ]


}
```