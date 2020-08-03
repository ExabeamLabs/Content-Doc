#### Parser Content
```Java
{
Name = raw-netscaler-ica-login
  Vendor = Citrix Netscaler
  Product = Citrix Netscaler
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ "SSLVPN ICASTART", "username:domainname" ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[^\s]+[^\s:])""",
   """\w+\s+\d+\s+\d\d:\d\d:\d\d\s+({host}[\w\-.]+)""",
    """({time}\d\d/\d\d/\d\d\d\d:\d\d:\d\d:\d\d)""",
    """username:domainname\s({user}[^:@]+)(:|@)({domain}[^\s]+[^\s:])?""",
    """Source\s({src_ip}[\w.:]+[^:]):\d+""",
    """Destination\s({dest_ip}[^:]+)""",
    """applicationName\s({app}.+?) - startTime"""
  ]
}
```