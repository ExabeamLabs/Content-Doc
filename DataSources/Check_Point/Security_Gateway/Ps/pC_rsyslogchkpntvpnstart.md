#### Parser Content
```Java
{
Name = r-syslog-chkpnt-vpn-start
  Vendor = Check Point 
  Product = Security Gateway
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """%CHKPNT-6-031085: authcrypt""", """connected to gateway""" ]
  Fields = [
    """connected to gateway,([^,]{0,2000},){14}({time}[^,]{1,2000})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """authcrypt,([^,]{0,2000}?,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """connected to gateway,([^,]{0,2000}?,)({user}[^,]{1,2000})""" ]
}
```