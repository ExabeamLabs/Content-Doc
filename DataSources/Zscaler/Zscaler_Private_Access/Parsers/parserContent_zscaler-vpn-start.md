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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """([^,]*,){2}({user_email}[^\s,]+),([^,]*,){6}({src_ip}[A-Fa-f:\d.]+),([^,]*,){3}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ),[^,]*,({bytes_in}\d{1,100}),({bytes_out}\d{1,100})"""
  ]
}
```