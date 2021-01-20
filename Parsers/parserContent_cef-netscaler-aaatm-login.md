#### Parser Content
```Java
{
Name = cef-netscaler-aaatm-login
  Vendor = Netscaler
  Product = Netscaler VPN
  Lms = Direct
  TimeFormat = "epoch"
  DataType = "remote-login"
  Conditions = [ """AAATM LOGIN""" ]
  Fields = [
    """User\s+({domain}[^\\]+)\\+({user}[^\s]+)"""
    """Client_ip\s+({src_ip}[^\s]+)""",
    """Vserver\s+(127.0.0.1|({host}[^:\s]+))"""
    """Browser_type\s+"+({user_agent}[^"]+)""",
    """SessionId:\s+({session_id}\d+)"""
    """rt=({time}\d+)"""
  ]
  DupFields = ["host->dest_host"]
}
```