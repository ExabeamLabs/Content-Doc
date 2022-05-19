#### Parser Content
```Java
{
Name = googlecloud-storage-activity
  Vendor = Google
  Product = Cloud Platform
  Lms = Direct
  DataType = "cloud-storage-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """googleapis.com""", """"serviceName":"storage""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S{1,2000})""",
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s(::ffff:)?({host}[\w\-.]{1,2000})\s\d{1,100}\s""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """callerIp":"({src_ip}[^"]{1,2000})""",
    """({service}storage.googleapis.com)""",
    """methodName":"({activity}[^"]{1,2000})""",
    """principalEmail":"(?:({user_email}[^"@]{1,2000}?@({email_domain}[^"@]{1,2000}))|({user}[^"]{1,2000}))"""",
    """callerSuppliedUserAgent":"({user_agent}[^"]{1,2000}?)\s{0,100}"""",
    """resource"[^\}]{1,2000}?location":"({region}[^"]{1,2000})""",
    """policyDelta"[^\}]{1,2000}?role":"roles\/({role}[^"\\\/]{1,2000})""",
    """status.+?"code":\d{1,100

}
```