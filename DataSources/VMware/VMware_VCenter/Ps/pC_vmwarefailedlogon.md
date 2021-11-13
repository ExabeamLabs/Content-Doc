#### Parser Content
```Java
{
Name = vmware-failed-logon
  Vendor = VMware
  Product = VMware VCenter
  Lms = Splunk
  DataType = "failed-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """vpxd[""", """] Event [""", """[error]""", """[Cannot login""", """[vim.event""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """\[({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)\]""",
    """\d\d:\d\d:\d\d\s({src_host}[^\s]{1,2000}) vpxd\[""",
    """\[vim.event.({failure_reason}[^\]]{1,2000})\]""",
    """\[Cannot login (user )?(({domain}[^\\]{1,2000})\\({user}[^@]{1,2000})|({=user}[^@]{1,2000})@({=domain}[^@]{1,2000}))@({dest_ip}[a-fA-F\d:.]{1,2000})(:\s({failure_reason}[^\]]{1,2000}))?\]"""
  ]


}
```