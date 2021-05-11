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
    """User\s{1,100}({domain}[^\\]+)\\+({user}[^\s]+)"""
    """Client_ip\s{1,100}({src_ip}[^\s]+)""",
    """Vserver\s{1,100}(127.0.0.1|({host}[^:\s]+))"""
    """Browser_type\s{1,100}"{1,20}({user_agent}[^"]+)""",
    """SessionId:\s{1,100}({session_id}\d{1,100})"""
    """rt=({time}\d{1,100})"""
  ]
  DupFields = ["host->dest_host"]
}
```