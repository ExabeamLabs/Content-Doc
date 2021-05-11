#### Parser Content
```Java
{
Name = vmware-ssh-login
  Vendor = VMware
  Product = VMware ESXi
  Lms = QRadar
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "EMC VMWare","Login Succeeded","Accepted ", " for user " ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\d\d.\d\d\d\w\s(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]+))\sHostd:""",
    """(exabeam_\w+=|^).+?Accepted ({auth}\S+) for user ({user}[^\s]+)""",
    """\s{1,100}from\s{1,100}(::[\w]+:)?({src_ip}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1))"""
  ]
}
```