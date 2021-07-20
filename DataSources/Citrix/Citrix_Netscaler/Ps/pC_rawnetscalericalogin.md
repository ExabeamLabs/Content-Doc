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
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000}[^\s:])""",
   """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})""",
    """({time}\d\d/\d\d/\d\d\d\d:\d\d:\d\d:\d\d)""",
    """username:domainname\s({user}[^:@]{1,2000})(:|@)({domain}[^\s]{1,2000}[^\s:])?""",
    """Source\s({src_ip}[\w.:]{1,2000}[^:]):\d{1,100}""",
    """Destination\s({dest_ip}[^:]{1,2000})""",
    """applicationName\s({app}.+?) - startTime"""
  ]
}
```