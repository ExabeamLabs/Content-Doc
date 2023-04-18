#### Parser Content
```Java
{
Name = o365-activity
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Workload""", """"ResultStatus""", """"Operation""" ]
  Fields = [
    """"CreationTime\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=(Unknown|({host}[\w\-.]{1,2000}))""",
    """"host\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}({host}[^"\\]{1,2000})""",
    """\sact=({activity}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """"Operation\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}({activity}[^"\\\.]{0,2000})""",
    """"eid\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}(Not Available|SecurityComplianceAlerts|({user_email}[^"@]{1,2000}?@[^@"]{1,2000}?)|({user}[^"]{1,2000}?))\\{0,20}"""",
    """UserKey"{0,20}:\s{0,100}"{0,20}({user_email}[^@"]{1,2000}@({email_domain}[^"]{1,2000}))"""",
    """"UserId\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}(({user_email}[^"\\@]{1,2000}?@({email_domain}([\.\w+]{1,2000}\.){0,256}[^\.\\\s"]{1,2000}?\.[^\\\s"\.>]{1,2000})>?\s{0,100})|(Not Available|(({domain}[^"\\\/]{1,2000})[\\\/])?(Unknown|((\w+?_)?(\w+-)?\w+-\w+-\w+-\w+)|({user}[^"\\\/@\s]{1,2000}?))))",""",
    """"MailboxOwnerUPN\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}({user_email}[^"\\\s@]{1,2000}@({email_domain}([\.\w+]{1,2000}\.){0,256}([^\\\.\s"]{1,2000}){0,256}\.[^\\\s"\.>]{1,2000}))>?\s{0,100}"{1,20}""",
    """"(Workload|Application|Client)\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}({app}[^"\\]{0,2000})""",
    """sourceServiceName =({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """"app"{1,20}:\{[^\}]{1,2000}?"displayName"{1,20}:"{1,20}({app}[^"]{1,2000})"""",
    """"ObjectId\\{0,20}"{1,20}:"?[\s\\]{0,2000}"{1,20}(Unknown|Not Available|({object}[^"\\]{0,2000}?))\s{0,100}"""",
    """"Client\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}({user_agent}[^"]{0,2000})""",
    """"UserAgent\\{0,20}"{1,20}:[\s\\]{0,2000}"(|({user_agent}[^=]{0,2000}?))\\*",""",
    """\{"{1,20}Name"{1,20}:[\s\\]{0,2000}"{1,20}UserAgent"{1,20

}
```