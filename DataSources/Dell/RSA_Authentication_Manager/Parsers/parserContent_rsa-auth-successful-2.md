#### Parser Content
```Java
{
Name = rsa-auth-successful-2
  Vendor = Dell
  Product = RSA Authentication Manager
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ SINGLEPOINT """, """ USER_AUTHN_CONDITION """, """,authenticationType=""" ]
  Fields = [
    """({host}[\w\-.]{1,2000}) \d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) \S+ SINGLEPOINT""",
    """USERNAME="({user}[^\s"]{1,2000})""",
    """POLICY="({auth_policy}[^"]{1,2000})""",
    """AUTH_CONDITION="({auth_condition}[^"]{1,2000})""",
    """ipAddress=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """DECIDING_RULE_SET="({deciding_rule_set}[^"]{1,2000})""",
    """RESOURCE="({resource}[^"]{1,2000})""",
    """authenticationType=({auth_method}[^",]{1,2000})""",
    """ACTION="({outcome}[^"]{1,2000})""",
    """UserAgent=({user_agent}[^"]{1,2000})""",
    """UserAgent=(Mozilla.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
  ]
}
```