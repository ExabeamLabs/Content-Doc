#### Parser Content
```Java
{
Name = azure-app-login
  Vendor = Microsoft
  Product = Azure
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = ["""|Skyformation|SkyFormation Cloud Apps Security|""", """"category":"ContainerRegistryLoginEvents"""", """"operationName":"Login""""]
  Fields = [
    """"loginServer":"({host}[^",]{1,2000})""",
    """"time":"({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,100}Z)""",
    """({app}ContainerRegistry)""",
    """({event_name}ContainerRegistryLoginEvents)""",
    """"identity":"(({user_email}[^@,]{1,2000}@[^",]{1,2000})|({user}[^",]{1,2000}))""",
    """"resultDescription":"({result_code}\d{1,100})""",
    """"callerIpAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"browser"{1,20}:"{1,20}({browser}[^"]{1,2000})"""",
    """"operatingSystem"{1,20}:"{1,20}({os}[^"]{1,2000})"""",
    """"userAgent":"({user_agent}[^"]{1,2000})"""",
    """"operationName":"({activity}[^",]{1,2000})""",
    """\[Namespace:\s{0,100}({event_hub_namespace}\S+) ; EventHub name:\s{0,100}({event_hub_name}[\w-]{1,2000})""",
  ]
    DupFields= ["event_hub_namespace->host"]


}
```