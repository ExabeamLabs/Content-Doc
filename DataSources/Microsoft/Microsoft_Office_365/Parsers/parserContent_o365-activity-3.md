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
    """"CreationTime\\*"+:[\s\\]*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """"Operation\\*"+:[\s\\]*"+({activity}[^"\\\.]*)""",
    """"UserId\\*"+:[\s\\]*"+(({domain}[^"\\]+)\\+)?(({user_email}[^@"]+@[^."]+\.[^"]+?)|(SecurityComplianceAlerts|(Unknown|Sync|({user}[^"@\\\s]*))))"""",
    """\ssuser=[^"@=\s]*?@([\.\w+]+\.)?({email_domain}[^\.\s"]+?\.[^\s"\.\\]+)""",
    """"UserId\\*"+:[\s\\]*"+({user_email}[^@"]+@[^."]+\.[^"]+?)"""",
    """"UserId\\*"+:[\s\\"]*"+[^"]*?@([\.\w+]+\.)?({email_domain}[^\.\s"]+?\.[^\s"\.>]+)>?\s*"+""",
    """"UserId":"\\*"(?![^@"]+?@[^\s"]+)({domain}[^"\\\/]+)[^"]*?(Unknown|Sync|({user}[^"\\\/@\s]+))\\"""",
    """"(Workload|Application|Client)\\*"+:[\s\\]*"+({app}[^"\\]*)""",
    """requestClientApplication=({app}[^=]+?)\s+(\w+=|$)""",
    """\WdestinationServiceName\s{0,100}=({app}[^=]+?)\s{1,100}(\w+=|$)""",
    """\WsourceServiceName=({app}[^=]+?)\s{1,100}(\w+=|$)""",
    """"ObjectId\\*"+:"?[\s\\]*"+(Unknown|Not Available|({object}[^"\\]*))""",
    """"SourceFileName":"({object}[^",]+)""",
    """\ssuser=(anonymous|SecurityComplianceAlerts|({user_email}[^\s]+@[^\s]+\.[^\s]+)|(Unknown|Sync|({user}[^"\s@]+?)))\s""",
    """\ssuser=({user_email}[^=@"]+@[^.="]+\.[^=]+?)\s\w+=""",
    """\ssuser=[^=\s]*?@([\.\w+]+\.)?({email_domain}[^\.\s"]+?\.[^\s"\.>]+)""",
    """"ItemName":"({subject}[^"]+)""",
    """Sender":"({sender}[^"]+)""",
    """"Receivers":\[({recipients}"({recipient}[^",]+)[^\]]+?)\],"""",
    """"ClientIP"+:"+({src_ip}[A-Fa-f:\d.]+)""",
    """UserAgent":\s*"({user_agent}[^"]+)"""",
    """DatasetName"*:\s*"*({data_set_name}[^"]+)""",
    """Workload"*:\s*"*({resource}[^"]+)"*""",
    """"TargetUserOrGroupName":"({target}[^"]+)"""",
    """cs2=({group_name}[^=]+)\s+\w+=""",
    """"IsSuccess":({outcome}[^\s,]+)"""
  ]
}
```