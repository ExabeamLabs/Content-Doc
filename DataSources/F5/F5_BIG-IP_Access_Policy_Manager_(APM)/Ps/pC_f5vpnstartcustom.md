#### Parser Content
```Java
{
Name = f5-vpn-start-custom
  Vendor = F5
  Product = F5 BIG-IP Access Policy Manager (APM)
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """<ACCESS_POLICY_COMPLETED>""", """Policy Result: allow""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[^\s]{1,2000})\s{1,100}({host}[^\s]{1,2000})\s{1,100}[^\s]{1,2000}\s{1,100}Rule.+?Session ID:\s{1,100}({session_id}[^\|]{1,2000})\|ClientIP:\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Username:({user}[^\s][^\|]{0,2000}?)\|""",
    """Username:\s({user}[^\s][^\|]{0,2000}?)\|""",
    """Username: n/a.+emailAddress=[^,]{1,2000}
}
```