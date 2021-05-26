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
    """connected to gateway,([^,]{0,2000}
```