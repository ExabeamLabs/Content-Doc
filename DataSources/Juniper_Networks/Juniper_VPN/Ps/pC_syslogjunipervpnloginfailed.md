#### Parser Content
```Java
{
Name = syslog-juniper-vpn-login-failed
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Syslog
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Host Checker policies could not be evaluated on host" ]
  Fields = [
    """ on host '({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}PulseSecure:\s{1,100}({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)\s{1,100}(\S+\s{1,100}){3}\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]\s{1,100}({user}[^\s\(\)]{1,2000})\((?:unknown|({realm}[^)]{1,2000}))\)""",
    """user=({user}[^\s]{1,2000})""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """proto=({protocol}[^\s]{1,2000})""",
    """msg="{1,20}({additional_info}[^"]{1,2000})""",
    """\Wfw=({firewall}[a-fA-F\d.:]{1,2000})""",
    """vpn=({host}[^\s]{1,2000})""",
    """time="{1,20}({time}[^"]{1,2000})"""
  ]
  DupFields = [ "dest_ip->host" ]


}
```