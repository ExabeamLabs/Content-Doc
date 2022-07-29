#### Parser Content
```Java
{
Name = s-mimecast-app-activity-1
  Vendor = Mimecast
  Product = Email Security
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"auditType":""", """destinationServiceName =Mimecast Email Security""", """dproc=Audit Events""", """"category":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"eventTime":"({time}\d{4}-\d{2}-\d{2}T(\d{2}:){2}\d{2}(\+|-)\d+?)"""",
    """user":"(|({user_email}[^@"]{1,2000}@({email_domain}[^@"]{1,2000}))|({user}[^",]{1,2000}?))"""",
    """"eventInfo":"({additional_info}[^"]{0,2000}?)("|\s{0,100}$)""",
    """Application:\s{0,100}({app}[^",=:]{1,2000}?)("|,|\s\S+=|\s\S+:)""",
    """\sIP:\s{0,100}({src_ip}[a-fA-F\d\.:]{1,2000}?)\s""",
    """"category":"({category}[^",\}]{1,2000}?)"""",
    """"auditType":"({activity}[^",]{1,2000}?)""""
  ]


}
```