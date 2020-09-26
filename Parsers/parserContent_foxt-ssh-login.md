#### Parser Content
```Java
{
Name = foxt-ssh-login
  Vendor = Fox BoKS ServerControl
  Product = Powertech Identity Access Manager (BoKs)
  Lms = Exabeam
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "sshd - sshlogin", "Successful login" ]
  Fields = [
    """clientTime="*({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)Z"*""",
    """\d\dZ\s+({host}[\w\-.]+)\s+sshd - sshlogin""",
    """user="*({user}[^"]+)"""",
    """ssh [^\s]+ using ({auth}.+?) from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({event_code}ssh)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```