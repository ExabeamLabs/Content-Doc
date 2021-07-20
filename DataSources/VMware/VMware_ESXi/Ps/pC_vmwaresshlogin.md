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
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\d\d.\d\d\d\w\s(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]{1,2000}))\sHostd:""",
    """(exabeam_\w+=|^).+?Accepted ({auth}\S+) for user ({user}[^\s]{1,2000})""",
    """\s{1,100}from\s{1,100}(::[\w]{1,2000}:)?({src_ip}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1))"""
  ]
}
```