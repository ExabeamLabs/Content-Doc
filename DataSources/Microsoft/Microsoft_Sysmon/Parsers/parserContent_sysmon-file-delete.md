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
    """exabeam_host=([^=@]+@\s{0,100})?({host}\S+)""",
    """({event_name}File Delete)""",
    """\s({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)\s""",
    """ProcessGuid:\s\{({process_guid}[^\}]+)\}""",
    """ProcessId:\s({pid}\d{1,100})""",
    """User:\s(NT|[^\\]+\\({user}[^\s]+))""",
    """Image:\s{1,100}({process}({directory}[^"]*?[\\\/]+)?({process_name}[^\s]+))\s{1,100}\w+:""",
    """TargetFilename:\s({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))\s{1,100}\w+:""",
    """MD5=({md5}[^,]+),""",
    """SHA256=({sha256}[^,]+),""",
  ]
}
```