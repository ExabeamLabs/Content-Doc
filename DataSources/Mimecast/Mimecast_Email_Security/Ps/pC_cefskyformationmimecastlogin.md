#### Parser Content
```Java
{
Name = cef-skyformation-mimecast-login
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""",""""auditType":""", """"User Logged On"""",  """destinationServiceName =Mimecast Email Security"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100})""",
    """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """\WdestinationServiceName =(|({event_subtype}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdproc=(|({dproc}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdtz=(|({dtz}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"auditType":"({activity}[^"]{1,2000})""",
    """\Wmsg=(|({additional_info}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """({outcome}(?i)success)""",
    """({app}Mimecast Email Security)""",
    """Application:\s{0,100}({service}[^,]{1,2000})""",
    """\WIP:\s{0,100}({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """"user":"({user_email}[^"]{1,2000})""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"({user_agent}[^"]{1,2000}?)"\s{0,100}[,\}\]]""",
  ]


}
```