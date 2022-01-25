#### Parser Content
```Java
{
Name = symantec-app-activity
  Vendor = Symantec
  Product = Symantec VIP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """TRANSACTION_TIMESTAMP: """"", """ACTION_TYPE: """"", """SUCCESS: """"", """MESSAGE_CODE: """"" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """TRANSACTION_TIMESTAMP:\s{0,100}""({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """ACTION_TYPE:\s{0,100}""({action}[^"]{1,2000})""",
    """SUCCESS:\s{0,100}""({outcome}[^"]{1,2000})""",
    """CLIENT_IP:\s{0,100}""({src_ip}[^"]{1,2000})""",
    """CLIENT_BROWSER_DATA:\s{0,100}""({user_agent}[^"]{1,2000})""",
    """CUST_LOGIN_ID:\s{0,100}""(({user_email}[^"@]{1,2000}@({email_domain}[^"@]{1,2000}))|({user}[^"]{1,2000}))""",
    """Mozilla\/[^"]{1,2000}\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """Mozilla\/[^"]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]


}
```