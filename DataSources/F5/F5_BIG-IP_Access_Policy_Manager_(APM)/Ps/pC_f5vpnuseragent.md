#### Parser Content
```Java
{
Name = f5-vpn-user-agent
  Vendor = F5
  Product = F5 BIG-IP Access Policy Manager (APM)
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490506:5:""" ]
  Fields = [
    """\s{1,100}01490506:5:\s{1,100}({session_id}[^:]{1,2000}):""",
    """\s{1,100}01490506:5:.*?({session_id}[^\s:]{1,2000}): Received User-Agent header""",
    """Received User-Agent header:\s{0,100}({user_agent}.+?)\s{0,100}$""",
  ]
}
```