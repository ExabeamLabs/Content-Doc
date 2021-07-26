#### Parser Content
```Java
{
Name = cef-netscaler-aaatm-login
  Vendor = Citrix
  Product = Citrix Netscaler VPN
  Lms = Direct
  TimeFormat = "epoch"
  DataType = "remote-login"
  Conditions = [ """AAATM LOGIN""" ]
  Fields = [
    """User\s{1,100}({domain}[^\\]{1,2000})\\+({user}[^\s]{1,2000})"""
    """Client_ip\s{1,100}({src_ip}[^\s]{1,2000})""",
    """Vserver\s{1,100}(127.0.0.1|({host}[^:\s]{1,2000}))"""
    """Browser_type\s{1,100}"{1,20}({user_agent}[^"]{1,2000})""",
    """SessionId:\s{1,100}({session_id}\d{1,100})"""
    """rt=({time}\d{1,100})"""
  ]
  DupFields = ["host->dest_host"]
}
```