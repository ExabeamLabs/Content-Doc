#### Parser Content
```Java
{
Name = googlecloud-app-activity
  Vendor = Google
  Product = Google Cloud Platform
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"protoPayload":""", """googleapis.com""", """"resourceName":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"timestamp":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"callerIp":\s*"({src_ip}[^"]+)""",
    """"callerSuppliedUserAgent":\s*"({user_agent}[^"]+)""",
    """"callerSuppliedUserAgent":\s*"[^"]*?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """"principalEmail":\s*"(?:({user_email}[^"@]+?@({email_domain}[^"@]+))|({user}[^"]+))"""",
    """"methodName":\s*"({activity}[^"]+)""",
    """"resourceName":\s*"({resource}[^"]+?)(\/)?({object}[^"\/]+)"""",
    """"serviceName":\s*"({app}[^"]+)""",
  ]
}
```