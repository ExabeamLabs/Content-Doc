#### Parser Content
```Java
{
Name = raw-netscaler-ica-login
  Vendor = Citrix
  Product = Citrix Netscaler
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ "SSLVPN ICASTART", "username:domainname" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+[^\s:])""",
   """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]+)""",
    """({time}\d\d/\d\d/\d\d\d\d:\d\d:\d\d:\d\d)""",
    """username:domainname\s({user}[^:@]+)(:|@)({domain}[^\s]+[^\s:])?""",
    """Source\s({src_ip}[\w.:]+[^:]):\d{1,100}""",
    """Destination\s({dest_ip}[^:]+)""",
    """applicationName\s({app}.+?) - startTime"""
  ]
}
```