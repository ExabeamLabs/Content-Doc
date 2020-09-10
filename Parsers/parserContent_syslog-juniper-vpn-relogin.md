#### Parser Content
```Java
{
Name = syslog-juniper-vpn-relogin
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Syslog
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ " PulseSecure:", " logged out from ", " because user started new session " ]
  Fields = [
    """({time}\d\d\d\d\-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\s({dest_host}[^\s]+)\s+PulseSecure:""",
    """\-\s+({user}[^\s]+)\/({domain}[^/]+?)\s+logged out from""",
    """\suser started new session from IP \(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)""",
  ]
  DupFields = [ "dest_host->host" ]
}
```