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
    """([^,]{0,2000}
```