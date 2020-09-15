#### Parser Content
```Java
{
Name = vdi-remote-login
  Vendor = VMware
  Product = VMware VDI
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [""",VDI_LOGIN""", """<custom_condition_cont_7819>""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d\/\d\/\d\d\s\d\d:\d\d),*({dest_host}[^,]+),*(({domain}[^\\,]+)\\)?[^,]+,*({src_host}[^,]+),*({src_ip}[A-Fa-f:\d.]+),*({user}[^,]+),*({outcome}[^,]+)""",
  ]
}
```