#### Parser Content
```Java
{
Name = openvpn-vpn-login
  Vendor = SSL Open VPN
  Product = SSL Open VPN
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ """] AUTH SUCCESS """, """pvt_google_auth_secret_locked""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d(\+|\-)\d{1,100}).*?AUTH SUCCESS""",
    """'user':\s{0,100}.*?'({user}[^\s,]+)',""",
    """auth succeeded on.*?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
```