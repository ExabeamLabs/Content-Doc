#### Parser Content
```Java
{
Name = o365-activity-3
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Workload""", """flexString1Label=application-action""", """"Operation""" ]
  Fields = [
    """"CreationTime\\*"{1,20}:[\s\\]{0,2000}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"Operation\\*"{1,20}:[\s\\]{0,2000}"{1,20}({activity}[^"\\\.]{0,2000})""",
    """"UserId\\*"{1,20}:[\s\\]{0,2000}"{1,20}(({domain}[^"\\]{1,2000})\\+)?(({user_email}[^@"]{1,2000}@[^."]{1,2000}\.[^"]{1,2000}?)|(SecurityComplianceAlerts|(Unknown|Sync|({user}[^"@\\\s]{0,2000}))))"""",
    """\ssuser=[^"@=\s]{0,2000}?@([\.\w+]{1,2000}\.)?({email_domain}[^\.\s"]{1,2000}?\.[^\s"\.\\]{1,2000})""",
    """"UserId\\*"{1,20}:[\s\\]{0,2000}"{1,20}({user_email}[^@"]{1,2000}@[^."]{1,2000}\.[^"]{1,2000}?)"""",
    """"UserId\\*"{1,20}:[\s\\"]{0,2000}"{1,20}[^"]{0,2000}?@([\.\w+]{1,2000}\.)?({email_domain}[^\.\s"]{1,2000}?\.[^\s"\.>]{1,2000})>?\s{0,100}"{1,20}""",
    """"UserId":"\\*"(?![^@"]{1,2000}?@[^\s"]{1,2000})({domain}[^"\\\/]{1,2000})[^"]{0,2000}?(Unknown|Sync|({user}[^"\\\/@\s]{1,2000}))\\"""",
    """"(Workload|Application|Client)\\*"{1,20}:[\s\\]{0,2000}"{1,20}({app}[^"\\]{0,2000})""",
    """requestClientApplication=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\WdestinationServiceName\s{0,100}=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\WsourceServiceName =({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """"ObjectId\\*"{1,20}:"?[\s\\]{0,2000}"{1,20}(Unknown|Not Available|({object}[^"\\]{0,2000}))""",
    """"SourceFileName":"({object}[^",]{1,2000})""",
    """\ssuser=(anonymous|SecurityComplianceAlerts|({user_email}[^\s]{1,2000}@[^\s]{1,2000}\.[^\s]{1,2000})|(Unknown|Sync|({user}[^"\s@]{1,2000}?)))\s""",
    """\ssuser=({user_email}[^=@"]{1,2000}@[^.="]{1,2000}\.[^=]{1,2000}?)\s\w+=""",
    """\ssuser=[^=\s]{0,2000}?@([\.\w+]{1,2000}\.)?({email_domain}[^\.\s"]{1,2000}?\.[^\s"\.>]{1,2000})""",
    """"ItemName":"({subject}[^"]{1,2000})""",
    """Sender":"({sender}[^"]{1,2000})""",
    """"Receivers":\[({recipients}"({recipient}[^",]{1,2000})[^\]]{1,2000}?)\],"""",
    """"ClientIP"{1,20}:"{1,20}\[?({src_ip}((\d{1,3}\.){3}\d{1,3}|[A-Fa-f\d]{1,2000}:[a-fA-F\d:]{1,2000}))\]?(:({src_port}\d{1,100}))?"""",
    """UserAgent":\s{0,100}"({user_agent}[^"]{1,2000})"""",
    """DatasetName"{0,20}:\s{0,100}"{0,20}({data_set_name}[^"]{1,2000})""",
    """Workload"{0,20}:\s{0,100}"{0,20}({resource}[^"]{1,2000})"{0,20}""",
    """"TargetUserOrGroupName":"({target}[^"]{1,2000})"""",
    """cs2=({group_name}[^=]{1,2000})\s{1,100}\w+=""",
    """"IsSuccess":({outcome}[^\s,]{1,2000})""",
    """SourceRelativeUrl":"({dest_path}[^"]{1,2000}?)\s{0,100}"""",
    """SiteUrl":"({site_url}[^"]{1,2000})""""
  ]


}
```