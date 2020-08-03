#### Parser Content
```Java
{
Name = rsa-auth-successful-2
  Vendor = Dell EMC
  Product = RSA Authentication Manager
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ SINGLEPOINT """, """ USER_AUTHN_CONDITION """, """,authenticationType=""" ]
  Fields = [
    """({host}[\w\-.]+) \d+ ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) \S+ SINGLEPOINT""",
    """USERNAME="({user}[^\s"]+)""",
    """POLICY="({auth_policy}[^"]+)""",
    """AUTH_CONDITION="({auth_condition}[^"]+)""",
    """ipAddress=({src_ip}[A-Fa-f:\d.]+)""",
    """DECIDING_RULE_SET="({deciding_rule_set}[^"]+)""",
    """RESOURCE="({resource}[^"]+)""",
    """authenticationType=({auth_method}[^",]+)""",
    """ACTION="({outcome}[^"]+)""",
    """UserAgent=({user_agent}[^"]+)""",
    """UserAgent=(Mozilla.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
  ]
}
```