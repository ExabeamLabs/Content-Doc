#### Parser Content
```Java
{
Name = vmware-remote-logon
  Vendor = VMware Horizon
  Product = VMware Horizon
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """starting channel ""","""connecting to target""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """exabeam_raw=.*?({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """connecting to target (?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s:]+))""",
    """User ({user}.+?) starting channel"""
   ]
}
```