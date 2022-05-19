#### Parser Content
```Java
{
Name = cef-carbonblack-file-write-4
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  TimeFormat = "epoch"
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """threatIndicators""" , """"eventType":"SYSTEM_API_CALL"""", """ attempted to write """ ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """"eventTime":({time}\d{1,100})""",
    """"deviceIpAddress":"({src_ip}[A-Fa-f:\d\.]{1,2000})""",
    """"deviceName":"(({domain}[^\\\s",]{1,2000})\\+)?({src_host}[^\\\s",]{1,2000})"""",
    """"email":"(({domain}[^\\",]{1,2000})\\+)?(SYSTEM|({user}[^\s",]{1,2000}))"""",
    """"userName":"(SYSTEM|({user}[^\s",]{1,2000}))"""",
    """({accesses}write)""",
    """"name":"({file_path}(({file_parent}[^"]{0,2000}?[\\\/]{1,20})?({file_name}[^\\\/"]{1,2000}?(\.({file_ext}[^"]{1,2000}))?)))""""
  ]


}
```