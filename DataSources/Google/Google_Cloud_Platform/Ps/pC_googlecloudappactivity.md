#### Parser Content
```Java
{
Name = googlecloud-app-activity
  Vendor = Google
  Product = Google Cloud Platform
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"protoPayload":""", """googleapis.com""", """"resourceName":""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S{1,2000})""",
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s(::ffff:)?({host}[\w\-.]{1,2000})\s\d{1,100}\s""",
    """"timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"callerIp":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"callerSuppliedUserAgent":\s{0,100}"({user_agent}[^"]{1,2000})""",
    """"principalEmail":\s{0,100}"(?:({user_email}[^"@]{1,2000}?@({email_domain}[^"@]{1,2000}))|({user}[^"]{1,2000}))"""",
    """"methodName":\s{0,100}"({activity}[^"]{1,2000})""",
    """"resourceName":\s{0,100}"({resource}[^"]{1,2000}?(\/({object}[^"\/]{1,2000}))?)"""",
    """"serviceName":\s{0,100}"({app}[^"]{1,2000})""",
    """\sdproc=({app}[^=]{1,2000})\s\w{1,2000}="""
  ]


}
```