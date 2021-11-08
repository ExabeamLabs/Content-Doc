#### Parser Content
```Java
{
Name = s-f5-vpn-p2
  Vendor = F5
  Product = F5 BIG-IP Access Policy Manager (APM)
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["""<ACCESS_POLICY_AGENT_EVENT>""", """session_id=""", """vpngroup="""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """\d\d:\d\d:\d\d\s{1,100}([^\/\s]{1,2000}\/)?({host}[^\s]{1,2000}).+?access_type=({vpn_type}[^\s]{1,2000})\suser=({user}[^\s]{1,2000}).+?vpngroup=({realm}[^\s]{1,2000})\ssession_id=({session_id}[^\s]{1,2000})\s{0,100}$"""
  ]
}
```