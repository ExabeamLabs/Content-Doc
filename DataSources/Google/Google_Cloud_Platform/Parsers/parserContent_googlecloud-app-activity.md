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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"callerIp":\s{0,100}"({src_ip}[^"]+)""",
    """"callerSuppliedUserAgent":\s{0,100}"({user_agent}[^"]+)""",
    """"callerSuppliedUserAgent":\s{0,100}"[^"]*?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """"principalEmail":\s{0,100}"(?:({user_email}[^"@]+?@({email_domain}[^"@]+))|({user}[^"]+))"""",
    """"methodName":\s{0,100}"({activity}[^"]+)""",
    """"resourceName":\s{0,100}"({resource}[^"]+?)(\/)?({object}[^"\/]+)"""",
    """"serviceName":\s{0,100}"({app}[^"]+)""",
  ]
}
```