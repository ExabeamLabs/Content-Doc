#### Parser Content
```Java
{
Name = cef-skyformation-mimecast-login
  Vendor = Mimecast
  Product = Email Security
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"auditType":""", """"User Logged On"""",  """destinationServiceName =Mimecast Email Security""","""dproc="""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100})""",
    """\WdestinationServiceName =(|({event_subtype}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdproc=(|({dproc}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"auditType":"({activity}[^"]{1,2000})""",
    """({outcome}(?i)success)""",
    """({app}Mimecast Email Security)""",
    """Application:\s{0,100}({service}[^,]{1,2000})""",
    """\WIP:\s{0,100}({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """"user":"({user_email}[^"]{1,2000})""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"({user_agent}[^"]{1,2000}?)"\s{0,100}[,\}\]]""",
  ]


}
```