#### Parser Content
```Java
{
Name = sysmon-file-delete
  Vendor = Microsoft
  Product = Sysmon
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """File Delete:""", """IMPHASH=""", """User:""" ]
  Fields = [
    """exabeam_host=([^=@]+@\s*)?({host}\S+)""",
    """({event_name}File Delete)""",
    """\s({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)\s""",
    """ProcessGuid:\s\{({process_guid}[^\}]+)\}""",
    """ProcessId:\s({pid}\d+)""",
    """User:\s(NT|[^\\]+\\({user}[^\s]+))""",
    """Image:\s+({process}({directory}[^"]*?[\\\/]+)?({process_name}[^\s]+))\s+\w+:""",
    """TargetFilename:\s({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))\s\w+:""",
    """MD5=({md5}[^,]+),""",
    """SHA256=({sha256}[^,]+),""",
  ]
}
```