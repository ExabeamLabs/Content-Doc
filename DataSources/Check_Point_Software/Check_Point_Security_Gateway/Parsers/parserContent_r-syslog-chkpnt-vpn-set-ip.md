#### Parser Content
```Java
{
Name = r-syslog-chkpnt-vpn-set-ip
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-set-ip"
  TimeFormat = "ddMMMyyyy  HH:mm:ss"
  Conditions = [ """%CHKPNT-6-031085: decrypt""" ]
  Fields = [
    """decrypt,([^,]{0,2000}
```