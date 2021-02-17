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
    """\w+\s+\d+\s+\d\d:\d\d:\d\d\s+({host}[\w\-.]+)""",
    """({time}\d\d/\d\d/\d\d\d\d:\d\d:\d\d:\d\d \w+)""",
    """User ({user_email}[^@\s]+@[^@\s]+) - Client_ip ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """User (({domain}[^\s\\]+)\\+)?({user}[^@\s\\]+) - Client_ip ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """ Failure_reason "({failure_reason}[^"]+)""",
    """ Browser .*?({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """Browser .*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  ]
}
```