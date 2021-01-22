#### Parser Content
```Java
{
Name = f5-vpn-user-agent
  Vendor = F5
  Product = Big-IP
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490506:5:""" ]
  Fields = [
    """\s+01490506:5:\s+({session_id}[^:]+):""",
    """Received User-Agent header:\s*({user_agent}.+?)\s*$""",
  ]
}
```