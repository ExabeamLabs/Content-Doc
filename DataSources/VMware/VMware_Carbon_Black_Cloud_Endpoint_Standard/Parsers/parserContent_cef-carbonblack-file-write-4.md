#### Parser Content
```Java
{
Name = cef-carbonblack-file-write-4
  Vendor = VMware
  Product = VMware Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  TimeFormat = "epoch"
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """CEF:""", """threatIndicators""" , """|security-threat-detected""", """act=run""", """attempted to write""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """"eventTime":({time}\d+)""",
    """"deviceIpAddress":"({src_ip}[A-Fa-f:\d\.]+)""",
    """"deviceName":"(({domain}[^\\\s",]+)\\+)?({src_host}[^\\\s",]+)"""",
    """"email":"(({domain}[^\\",]+)\\+)?(SYSTEM|({user}[^\s",]+))"""",
    """"userName":"(SYSTEM|({user}[^\s",]+))"""",
    """({accesses}write)""",
    """fname=({file_path}(({file_parent}[^=]*?[\\\/]+)?({file_name}[^\\\/=]+?(\.({file_ext}\w+))?)))\s+\w+="""
  ]
}
```