#### Parser Content
```Java
{
Name = r-syslog-chkpnt-vpn-set-ip
  Vendor = Check Point 
  Product = Security Gateway
  Lms = Direct
  DataType = "vpn-set-ip"
  TimeFormat = "ddMMMyyyy  HH:mm:ss"
  Conditions = [ """%CHKPNT-6-031085: decrypt""" ]
  Fields = [
    """decrypt,([^,]{0,2000},){33}({time}[^,]{1,2000})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """decrypt,([^,]{0,2000}?,){3}({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """decrypt,([^,]{0,2000}?,){40}({user}[^,]{1,2000})""" ]
}
```