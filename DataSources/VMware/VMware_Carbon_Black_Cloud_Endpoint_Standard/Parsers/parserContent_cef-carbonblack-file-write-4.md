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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """"eventTime":({time}\d{1,100})""",
    """"deviceIpAddress":"({src_ip}[A-Fa-f:\d\.]{1,2000})""",
    """"deviceName":"(({domain}[^\\\s",]{1,2000})\\+)?({src_host}[^\\\s",]{1,2000})"""",
    """"email":"(({domain}[^\\",]{1,2000})\\+)?(SYSTEM|({user}[^\s",]{1,2000}))"""",
    """"userName":"(SYSTEM|({user}[^\s",]{1,2000}))"""",
    """({accesses}write)""",
    """fname=({file_path}(({file_parent}[^=]{0,2000}?[\\\/]{1,2000})?({file_name}[^\\\/=]{1,2000}?(\.({file_ext}\w+))?)))\s{1,100}\w+="""
  ]
}
```