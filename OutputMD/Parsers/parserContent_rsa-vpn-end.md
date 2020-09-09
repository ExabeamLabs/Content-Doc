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
    """<\d+>\w+ \d+ \d+:\d+:\d+ ({host}[\w.\-]+)""",
    """\sUSER_AGENT="({user_agent}[^"]+)""",
    """\sSESSION_INACTIVITY_TIMEOUT="({time}\w+ \w+ \d+ \d+:\d+:\d+ \w+ \d\d\d\d)""",
    """\sUSERNAME="({user}[^"]+)""",
    """\sREMOTE_IP="({src_ip}[a-fA-F\d.:]+)""",
    """\sSESSION_ID="({session_id}[^"]+)""",
    """\sREASON="({reason}[^"]+)""",
    """({dest_ip}[a-fA-F\d.:]+)(\s+\S+){2}\s+USER_SESSION_REMOVED_TIMEOUT"""
  ]
  DupFields = ["host->dest_host"]
}
```