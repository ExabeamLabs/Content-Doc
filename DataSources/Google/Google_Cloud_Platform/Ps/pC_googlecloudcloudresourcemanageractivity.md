#### Parser Content
```Java
{
Name = googlecloud-cloudresourcemanager-activity
  Vendor = Google
  Product = Google Cloud Platform
  Lms = Direct
  DataType = "cloud-admin-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"protoPayload":""", """googleapis.com""", """"serviceName":"cloudresourcemanager""" ]
  Fields = [
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s(::ffff:)?({host}[\w\-.]{1,2000})\s\d{1,100}\s""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"callerIp":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """:"({service}cloudresourcemanager.googleapis.com)""",
    """"methodName":"({activity}[^"]{1,2000})"""",
    """"principalEmail":"({user_email}[^"@]{1,2000}@({email_domain}[^"@.]{1,2000}\.[^"@]{1,2000})|({user}[^"]{1,2000}))"""",
    """"callerSuppliedUserAgent":"({user_agent}[^"]{1,2000})"""",
    """\{"bindingDeltas"[^=]{1,200}?"role":"roles\/({role}[^"\\\/]{1,200})""",
    """"message":"({failure_reason}[^"]{1,2000})""""
  ]
}
}
```