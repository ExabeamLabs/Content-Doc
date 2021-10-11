#### Parser Content
```Java
{
Name = zscaler-vpn-end
  Vendor = Zscaler
  Product = Zscaler Private Access
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """,ZPN_STATUS_DISCONNECTED,""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """([^,]{0,2000},){2}({user_email}[^\s,]{1,2000}),([^,]{0,2000},){6}({src_ip}[A-Fa-f:\d.]{1,2000}),([^,]{0,2000},){3}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ),[^,]{0,2000},({bytes_in}\d{1,100}),({bytes_out}\d{1,100})"""
  ]
}
```