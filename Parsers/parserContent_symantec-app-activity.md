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
    """exabeam_host=({host}[\w.\-]+)""",
    """TRANSACTION_TIMESTAMP:\s*""({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """ACTION_TYPE:\s*""({action}[^"]+)""",
    """SUCCESS:\s*""({outcome}[^"]+)""",
    """CLIENT_IP:\s*""({src_ip}[^"]+)""",
    """CLIENT_BROWSER_DATA:\s*""({user_agent}[^"]+)""",
    """CUST_LOGIN_ID:\s*""(({user_email}[^"@]+@({email_domain}[^"@]+))|({user}[^"]+))""",
    """Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """Mozilla\/[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
}
```