#### Parser Content
```Java
{
Name = r-syslog-chkpnt-vpn-end
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """%CHKPNT-6-031085: authcrypt""", """disconnected from gateway""" ]
  Fields = [
    """disconnected from gateway,([^,]{0,2000

}
```