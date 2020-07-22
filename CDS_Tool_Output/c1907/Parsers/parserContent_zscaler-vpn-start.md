#### Parser Content
```Java
{
Name = zscaler-vpn-start
  Vendor = Zscaler
  Product = Zscaler Private Access
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """,ZPN_STATUS_AUTHENTICATED,""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """([^,]*,){2}({user_email}[^\s,]+),([^,]*,){6}({src_ip}[A-Fa-f:\d.]+),([^,]*,){3}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ),[^,]*,({bytes_in}\d+),({bytes_out}\d+)"""
  ]
}
```