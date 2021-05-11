#### Parser Content
```Java
{
Name = rsa-auth-successful-1
  Vendor = Dell
  Product = RSA Authentication Manager
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ SINGLEPOINT """, """ USER_LOGIN """, """ AUTHN_TYPE="""" ]
  Fields = [
    """({host}[\w\-.]+) \d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) \S+ SINGLEPOINT""",
    """USERNAME="({user}[^\s"]+)""",
    """REMOTE_IP="({src_ip}[^"]+)""",
    """RESULT="({outcome}[^"]+)""",
    """SESSION_ID="({session_id}[^"]+)""",
    """AUTHN_TYPE="({auth_method}[^"]+)""",
    """NOT_AUTHNED_REASON="({failure_reason}[^"]+)""",
    """USER_AGENT="({user_agent}[^"]+)""",
    """USER_AGENT="(Mozilla.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
  ]
}
```