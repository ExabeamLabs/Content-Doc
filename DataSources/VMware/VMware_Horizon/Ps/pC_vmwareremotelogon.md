#### Parser Content
```Java
{
Name = vmware-remote-logon
  Vendor = VMware
  Product = VMware Horizon
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """starting channel ""","""connecting to target""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """exabeam_raw=.*?({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """connecting to target (?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s:]{1,2000}))""",
    """User ({user}.+?) starting channel"""
   ]
}
```