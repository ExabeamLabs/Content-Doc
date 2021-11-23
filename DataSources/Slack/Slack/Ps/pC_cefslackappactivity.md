#### Parser Content
```Java
{
Name = cef-slack-app-activity
  Vendor = Slack
  Product = Slack
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """destinationServiceName =Slack""", """"action":"""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)\s{1,100}""",
    """\WdestinationServiceName =({app}Slack)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """user":\{"id":"({user_id}[^"]{1,2000})","name":"({user_fullname}[^"]{1,2000})"""",
    """"email":"(|({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}?)))"""",
    """action":"({activity}[^"]{1,2000})""",
    """"ip_address":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """"entity":\{"[^"]{1,2000}":"[^"]{1,2000}","[^"]{1,2000}":\{("[^"]{1,2000}":"[^"]{1,2000}",){2}"name":"({object}[^"]{1,2000})"""",
    """"domain":"({domain}[^"]{1,2000})"""",
  ]


}
```