#### Parser Content
```Java
{
Name = foxt-ssh-login
  Vendor = HelpSystems
  Product = Powertech Identity Access Manager (BoKs)
  Lms = Exabeam
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "sshd - sshlogin", "Successful login" ]
  Fields = [
    """clientTime="{0,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)Z"{0,20}""",
    """\d\dZ\s{1,100}({host}[\w\-.]+)\s{1,100}sshd - sshlogin""",
    """user="{0,20}({user}[^"]+)"""",
    """ssh [^\s]+ using ({auth}.+?) from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({event_code}ssh)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```