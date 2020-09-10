#### Parser Content
```Java
{
Name = o365-activity-3
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Workload""", """flexString1Label=application-action""", """"Operation""" ]
  Fields = [
    """"CreationTime\\*"+:[\s\\]*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """"Operation\\*"+:[\s\\]*"+({activity}[^"\\\.]*)""",
    """"UserId\\*"+:[\s\\]*"+(({domain}[^"\\]+)\\+)?(({user_email}[^\s"@]+@[^\s"@]+)|(SecurityComplianceAlerts|(Unknown|({user}[^"@\\\s]*))))"""",
    """\ssuser=[^"@=\s]*?@([\.\w+]+\.)?({email_domain}[^\.\s"]+?\.[^\s"\.\\]+)""",
    """"UserId\\*"+:[\s\\]*"+({user_email}[^"\\@]+?@[^"\\\s@]+)""",
    """"UserId\\*"+:[\s\\"]*"+[^"]*?@([\.\w+]+\.)?({email_domain}[^\.\s"]+?\.[^\s"\.>]+)>?\s*"+""",
    """"UserId":"\\*"(?![^@"]+?@[^\s"]+)({domain}[^"\\\/]+)[^"]*?(Unknown|({user}[^"\\\/@\s]+))\\"""",
    """destinationServiceName=({app}.*?)\s*deviceInboundInterface""",
    """"(Workload|Application|Client)\\*"+:[\s\\]*"+({app}[^"\\]*)""",
    """requestClientApplication=({app}.+?)\s+(\w+=|$)""",
    """"ObjectId\\*"+:"?[\s\\]*"+(Unknown|Not Available|({object}[^"\\]*))""",
    """\ssuser=(anonymous|SecurityComplianceAlerts|({user_email}[^\s]+@[^\s]+\.[^\s]+)|(Unknown|({user}[^"\s@]+?)))\s""",
    """\ssuser=({user_email}[^"\\\s@]+@[^"\\\s@]+)""",
    """\ssuser=[^=\s]*?@([\.\w+]+\.)?({email_domain}[^\.\s"]+?\.[^\s"\.>]+)""",
    """ext_rawDataJson_ItemName=({subject}.+?)\s\w+="""
    """Sender":"({sender}[^"]+)""",
    """Receivers":({recipients}.+?\]),"""",
    """Receivers":\["({recipient}[^"]+)""",
    """"ClientIP"+:"+({src_ip}[A-Fa-f:\d.]+)""",
    """UserAgent"*:\s*"*({user_agent}[^"]+)""",
    """DatasetName"*:\s*"*({data_set_name}[^"]+)""",
    """Workload"*:\s*"*({resource}[^"]+)"*""",
    """"IsSuccess":({outcome}[^\s,]+)"""
  ]
}
```