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
    """"CreationTime\\*"{1,20}:[\s\\]*"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """\Wdvc=({host}\S+)""",
    """\Wdvchost=(Unknown|({host}[\w\-.]+))""",
    """"host\\*"{1,20}:[\s\\]*"{1,20}({host}[^"\\]+)""",
    """\Wact=({activity}[^=]+?)\s{1,100}(\w+=|$)""",
    """"Operation\\*"{1,20}:[\s\\]*"{1,20}({activity}[^"\\\.]*)""",
    """"eid\\*"{1,20}:[\s\\]*"{1,20}(Not Available|SecurityComplianceAlerts|({user_email}[^"@]+?@[^@"]+?)|({user}[^"]+?))\\*"""",
    """UserKey"{0,20}:\s{0,100}"{0,20}({user_email}[^@"]+@({email_domain}[^"]+))"""",
    """"UserId\\*"{1,20}:[\s\\]*"{1,20}(({domain}[^"\\]+)\\+)?(({user_email}[^\s"@]+@[^\s"@]+)|(Not Available|SecurityComplianceAlerts|(Unknown|((\w+?_)?(\w+-)?\w+-\w+-\w+-\w+)|({user}[^"@\\\s]*))))"""",
    """"MailboxOwnerUPN\\*"{1,20}:[\s\\]*"{1,20}({user_email}[^"@\\]+@[^"@\\]+)""",
    """\ssuser=[^"@=\s]*?@({email_domain}([\.\w+]+\.){0,256}([^\.\s"]+?\.[^\s"\.\\]+))""",
    """"UserId\\*"{1,20}:[\s\\]*"{1,20}({user_email}[^"\\@]+?@[^"\\\s@]+)""",
    """"UserId\\*"{1,20}:[\s\\"]*"{1,20}[^"]*?@({email_domain}([\.\w+]+\.){0,256}[^\.\s"]+?\.[^\s"\.>]+)>?\s{0,100}"{1,20}""",
    """"UserId":"\\*"(?![^@"]+?@[^\s"]+)(Not Available|({domain}[^"\\\/]+)[^"]*?(Unknown|((\w+?_)?(\w+-)?\w+-\w+-\w+-\w+)|({user}[^"\\\/@\s]+)))""",
    """"MailboxOwnerUPN\\*"{1,20}:[\s\\]*"{1,20}({user_email}[^"\\\s@]+@[^"\\\s@]+)""",
    """"MailboxOwnerUPN\\*"{1,20}:[\s\\"]*"{1,20}[^"]*?@({email_domain}([\.\w+]+\.){0,256}([^\.\s"]+){0,256}\.[^\s"\.>]+)>?\s{0,100}"{1,20}""",
    """"(Workload|Application|Client)\\*"{1,20}:[\s\\]*"{1,20}({app}[^"\\]*)""",
    """requestClientApplication=({app}[^=]+?)\s{1,100}(\w+=|$)""",
    """sourceServiceName=({app}[^=]+?)\s{1,100}(\w+=|$)""",
    """"ObjectId\\*"{1,20}:"?[\s\\]*"{1,20}(Unknown|Not Available|({object}[^"\\]*?))\s{0,100}"""",
    """"Client\\*"{1,20}:[\s\\]*"{1,20}({user_agent}[^"]*)""",
    """"UserAgent\\*"{1,20}:[\s\\]*"{1,20}({user_agent}[^=]*?)\\*"{1,20}
```