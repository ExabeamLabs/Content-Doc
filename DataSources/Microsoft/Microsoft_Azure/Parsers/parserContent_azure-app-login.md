#### Parser Content
```Java
{
Name = azure-app-login
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = ["""|Skyformation|SkyFormation Cloud Apps Security|""", """"category":"ContainerRegistryLoginEvents"""", """"operationName":"Login""""]
  Fields = [
    """"loginServer":"({host}[^",]+)""",
    """"time":"({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,100}Z)""",
    """({app}ContainerRegistry)""",
    """({event_name}ContainerRegistryLoginEvents)""",
    """"identity":"(({user_email}[^@,]+@[^",]+)|({user}[^",]+))""",
    """"resultDescription":"({result_code}\d{1,100})""",
    """"callerIpAddress":"({src_ip}[A-Fa-f:\d.]+)""",
    """"userAgent":"({user_agent}[^"]+)"""",
    """"operationName":"({activity}[^",]+)""",
    """"userAgent":".+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin|Ubuntu)""",
    """\[Namespace:\s{0,100}({event_hub_namespace}\S+) ; EventHub name:\s{0,100}({event_hub_name}[\w-]+)""",
  ]
    DupFields= ["event_hub_namespace->host"]
}
```