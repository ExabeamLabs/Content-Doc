#### Parser Content
```Java
{
Name = r-syslog-chkpnt-vpn-start
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """%CHKPNT-6-031085: authcrypt""", """connected to gateway""" ]
  Fields = [
    """connected to gateway,([^,]*,){14}({time}[^,]+)""",
    """exabeam_host=({host}[^\s]+)""",
    """authcrypt,([^,]*?,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """connected to gateway,([^,]*?,)({user}[^,]+)""" ]
}
```