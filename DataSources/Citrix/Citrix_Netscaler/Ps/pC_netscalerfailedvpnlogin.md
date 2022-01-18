#### Parser Content
```Java
{
Name = netscaler-failed-vpn-login
  Vendor = Citrix
  Product = Citrix Netscaler
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss z"
  Conditions = [ "LOGIN_FAILED", " Client_ip " ]
  Fields = [
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})""",
    """({time}\d\d/\d\d/\d\d\d\d:\d\d:\d\d:\d\d \w+)""",
    """User ({user_email}[^@\s]{1,2000}@[^@\s]{1,2000}) - Client_ip ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """User (({domain}[^\s\\]{1,2000})\\+)?({user}[^@\s\\]{1,2000}) - Client_ip ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """ Failure_reason "({failure_reason}[^"]{1,2000})""",
    """ Browser .*?({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """Browser .*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  ]


}
```