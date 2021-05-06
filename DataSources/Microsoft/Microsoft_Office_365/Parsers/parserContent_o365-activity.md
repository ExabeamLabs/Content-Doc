#### Parser Content
```Java
{
Name = o365-activity
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Workload""", """"ResultStatus""", """"Operation""" ]
  Fields = [
    """"CreationTime\\*"+:[\s\\]*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """\Wdvc=({host}\S+)""",
    """\Wdvchost=(Unknown|({host}[\w\-.]+))""",
    """"host\\*"+:[\s\\]*"+({host}[^"\\]+)""",
    """\Wact=({activity}[^=]+?)\s+(\w+=|$)""",
    """"Operation\\*"+:[\s\\]*"+({activity}[^"\\\.]*)""",
    """"eid\\*"+:[\s\\]*"+(Not Available|SecurityComplianceAlerts|({user_email}[^"@]+?@[^@"]+?)|({user}[^"]+?))\\*"""",
    """UserKey"*:\s*"*({user_email}[^@"]+@({email_domain}[^"]+))"""",
    """"UserId\\*"+:[\s\\]*"+(({domain}[^"\\]+)\\+)?(({user_email}[^\s"@]+@[^\s"@]+)|(Not Available|SecurityComplianceAlerts|(Unknown|((\w+?_)?(\w+-)?\w+-\w+-\w+-\w+)|({user}[^"@\\\s]*))))"""",
    """"MailboxOwnerUPN\\*"+:[\s\\]*"+({user_email}[^"@\\]+@[^"@\\]+)""",
    """\ssuser=[^"@=\s]*?@({email_domain}([\.\w+]+\.){0,256}([^\.\s"]+?\.[^\s"\.\\]+))""",
    """"UserId\\*"+:[\s\\]*"+({user_email}[^"\\@]+?@[^"\\\s@]+)""",
    """"UserId\\*"+:[\s\\"]*"+[^"]*?@({email_domain}([\.\w+]+\.){0,256}[^\.\s"]+?\.[^\s"\.>]+)>?\s*"+""",
    """"UserId":"\\*"(?![^@"]+?@[^\s"]+)(Not Available|({domain}[^"\\\/]+)[^"]*?(Unknown|((\w+?_)?(\w+-)?\w+-\w+-\w+-\w+)|({user}[^"\\\/@\s]+)))""",
    """"MailboxOwnerUPN\\*"+:[\s\\]*"+({user_email}[^"\\\s@]+@[^"\\\s@]+)""",
    """"MailboxOwnerUPN\\*"+:[\s\\"]*"+[^"]*?@({email_domain}([\.\w+]+\.){0,256}([^\.\s"]+){0,256}\.[^\s"\.>]+)>?\s*"+""",
    """"(Workload|Application|Client)\\*"+:[\s\\]*"+({app}[^"\\]*)""",
    """requestClientApplication=({app}[^=]+?)\s+(\w+=|$)""",
    """sourceServiceName=({app}[^=]+?)\s+(\w+=|$)""",
    """"ObjectId\\*"+:"?[\s\\]*"+(Unknown|Not Available|({object}[^"\\]*?))\s*"""",
    """"Client\\*"+:[\s\\]*"+({user_agent}[^"]*)""",
    """"UserAgent\\*"+:[\s\\]*"+({user_agent}[^=]*?)\\*"+,""",
    """\{"+Name"+:[\s\\]*"+UserAgent"+,"+Value"+:"+({user_agent}[^"]+)"+\}""",
    """"+Value"+:\s*"+({user_agent}[^"]+)"+,\s*"+Name"+:[\s\\]*"+UserAgent"+\}
```