#### Parser Content
```Java
{
Name = rsa-vpn-end
  Vendor = RSA
  Product = SecurID
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "EEE MMM dd HH:mm:ss z yyyy"
  Conditions = [ """USER_SESSION_REMOVED_TIMEOUT""", """SESSION_ID=""" ]
  Fields = [
    """<\d{1,100}>\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} ({host}[\w.\-]{1,2000})""",
    """\sUSER_AGENT="({user_agent}[^"]{1,2000})""",
    """\sSESSION_INACTIVITY_TIMEOUT="({time}\w+ \w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \w+ \d\d\d\d)""",
    """\sUSERNAME="({user}[^"]{1,2000})""",
    """\sREMOTE_IP="({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sSESSION_ID="({session_id}[^"]{1,2000})""",
    """\sREASON="({reason}[^"]{1,2000})""",
    """({dest_ip}[a-fA-F\d.:]{1,2000})(\s{1,100}\S+){2}\s{1,100}USER_SESSION_REMOVED_TIMEOUT"""
  ]
  DupFields = ["host->dest_host"]
}
```