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
    """decrypt,([^,]*,){33}({time}[^,]+)""",
    """exabeam_host=({host}[^\s]+)""",
    """decrypt,([^,]*?,){3}({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """decrypt,([^,]*?,){40}({user}[^,]+)""" ]
}
```