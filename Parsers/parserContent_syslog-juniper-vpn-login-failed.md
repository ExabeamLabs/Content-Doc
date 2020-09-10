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
    """({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+PulseSecure:\s+({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)\s+(\S+\s+){3}\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]\s+({user}[^\s\(\)]+)\((?:unknown|({realm}[^)]+))\)"""
  ]
  DupFields = [ "dest_ip->host" ]
}
```