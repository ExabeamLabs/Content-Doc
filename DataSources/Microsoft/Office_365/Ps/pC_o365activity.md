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
    """sourceServiceName=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """"ObjectId\\{0,20}"{1,20}:"?[\s\\]{0,2000}"{1,20}(Unknown|Not Available|({object}[^"\\]{0,2000}?))\s{0,100}"""",
    """"Client\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}({user_agent}[^"]{0,2000})""",
    """"UserAgent\\{0,20}"{1,20}:[\s\\]{0,2000}"(|({user_agent}[^=]{0,2000}?))\\*",""",
    """\{"{1,20}Name"{1,20}:[\s\\]{0,2000}"{1,20}UserAgent"{1,20},"{1,20}Value"{1,20}:"{1,20}({user_agent}[^"]{1,2000})"{1,20}\}""",
    """"{1,20}Value"{1,20}:\s{0,100}"{1,20}({user_agent}[^"]{1,2000})"{1,20},\s{0,100}"{1,20}Name"{1,20}:[\s\\]{0,2000}"{1,20}UserAgent"{1,20}\},""",
    """"Parameters"{1,20}:[\s\\]{0,2000}\[({additional_info}[^=]{1,2000}?)\s{0,100}\]""",
    """"ExtendedProperties"[^]]{0,2000}?UserAgent"{1,20},\s{0,100}"{1,20}Value"{1,20}:\s{0,100}"{1,20}({user_agent}[^"]{1,2000})""",
    """"AffectedItems"{1,20}:[\s\\]{0,2000}\[({additional_info}[^=]{1,2000}?)\s{0,100}\],""",
    """"ClientIP\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}\[?((0\.0\.0\.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\]?(:({src_port}\d{1,100}))|((0\.0\.0\.0|({=src_ip}[a-fA-F\d.:]{1,2000}))\]?(:({=src_port}\d{1,100}))?))"""",
    """\ssuser=((Not Available|anonymous|SecurityComplianceAlerts|({user_email}[^\s\\@"]{1,2000}@({email_domain}[^\\\s@\."]{1,2000}\.[^\s"]{1,2000}))|(Unknown|(\w+?_)?(\w+-)?\w+-\w+-\w+-\w+|((({domain}[^\\\s]{1,2000})\\)?({user}[^"\s@]{1,2000}?)))))\s""",
    """"ClientIPAddress\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}\[?(::1|({src_ip}[a-fA-F\d.:]{1,2000}))\]?(:({src_port}\d{1,100}))?""",
    """\sreason=(?:None|({failure_reason}[^\s]{1,2000}))""",
    """\{"Value": "(?:None|({failure_reason}[^"]{1,2000}))", "Name": "MethodExecutionResult."\}""",
    """"Path":"(\\+)?(\?+|({object}[^=]{1,2000}?))\s{0,100}"""",
    """"Subject":"\s{0,100}({additional_info}[^"]{1,2000}?)\s{0,100}"""",
    """"trc":"({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})""",
    """src-account-name":"({account_name}[^"]{1,2000})""",
    """OriginatingServer":"({src_host}[^\s"]{1,2000})""",
    """Workload"{0,20}:\s{0,100}"{0,20}({resource}[^"]{1,2000})"""",
    """"Path":"(\\+)?(\?+|({target}[^"\}\]]{1,2000}?))\s{0,100}"""",
    """Recipients":\[?"({target}[^\s,;@"]{1,2000}@({target_domain}[^\s;,"]{1,2000}))""",
    """"ResultStatus":\s{0,100}"({outcome}Success|Succeeded|Failed|Failure)"""
  ]
  DupFields = ["outcome->result","activity->event_name"]
}
```