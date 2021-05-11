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
    """"CreationTime\\*"{1,20}:[\s\\]*"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """"Operation\\*"{1,20}:[\s\\]*"{1,20}({activity}[^"\\\.]*)""",
    """"UserId\\*"{1,20}:[\s\\]*"{1,20}(({domain}[^"\\]+)\\+)?(({user_email}[^@"]+@[^."]+\.[^"]+?)|(SecurityComplianceAlerts|(Unknown|Sync|({user}[^"@\\\s]*))))"""",
    """\ssuser=[^"@=\s]*?@([\.\w+]+\.)?({email_domain}[^\.\s"]+?\.[^\s"\.\\]+)""",
    """"UserId\\*"{1,20}:[\s\\]*"{1,20}({user_email}[^@"]+@[^."]+\.[^"]+?)"""",
    """"UserId\\*"{1,20}:[\s\\"]*"{1,20}[^"]*?@([\.\w+]+\.)?({email_domain}[^\.\s"]+?\.[^\s"\.>]+)>?\s{0,100}"{1,20}""",
    """"UserId":"\\*"(?![^@"]+?@[^\s"]+)({domain}[^"\\\/]+)[^"]*?(Unknown|Sync|({user}[^"\\\/@\s]+))\\"""",
    """"(Workload|Application|Client)\\*"{1,20}:[\s\\]*"{1,20}({app}[^"\\]*)""",
    """requestClientApplication=({app}[^=]+?)\s{1,100}(\w+=|$)""",
    """\WdestinationServiceName\s{0,100}=({app}[^=]+?)\s{1,100}(\w+=|$)""",
    """\WsourceServiceName=({app}[^=]+?)\s{1,100}(\w+=|$)""",
    """"ObjectId\\*"{1,20}:"?[\s\\]*"{1,20}(Unknown|Not Available|({object}[^"\\]*))""",
    """"SourceFileName":"({object}[^",]+)""",
    """\ssuser=(anonymous|SecurityComplianceAlerts|({user_email}[^\s]+@[^\s]+\.[^\s]+)|(Unknown|Sync|({user}[^"\s@]+?)))\s""",
    """\ssuser=({user_email}[^=@"]+@[^.="]+\.[^=]+?)\s\w+=""",
    """\ssuser=[^=\s]*?@([\.\w+]+\.)?({email_domain}[^\.\s"]+?\.[^\s"\.>]+)""",
    """"ItemName":"({subject}[^"]+)""",
    """Sender":"({sender}[^"]+)""",
    """"Receivers":\[({recipients}"({recipient}[^",]+)[^\]]+?)\],"""",
    """"ClientIP"{1,20}:"{1,20}({src_ip}[A-Fa-f:\d.]+)""",
    """UserAgent":\s{0,100}"({user_agent}[^"]+)"""",
    """DatasetName"{0,20}:\s{0,100}"{0,20}({data_set_name}[^"]+)""",
    """Workload"{0,20}:\s{0,100}"{0,20}({resource}[^"]+)"{0,20}""",
    """"TargetUserOrGroupName":"({target}[^"]+)"""",
    """cs2=({group_name}[^=]+)\s{1,100}\w+=""",
    """"IsSuccess":({outcome}[^\s,]+)"""
  ]
}
```