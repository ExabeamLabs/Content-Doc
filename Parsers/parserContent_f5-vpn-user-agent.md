#### Parser Content
```Java
{
Name = f5-vpn-user-agent
  Vendor = F5 Networks
  Product = Big-IP
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490506:5:""" ]
  Fields = [
    """\s+01490506:5:\s+({session_id}[^:]+):""",
    """\s+01490506:5:.*?({session_id}[^\s:]+): Received User-Agent header""",
    """Received User-Agent header:\s*({user_agent}.+?)\s*$""",
  ]
}
```