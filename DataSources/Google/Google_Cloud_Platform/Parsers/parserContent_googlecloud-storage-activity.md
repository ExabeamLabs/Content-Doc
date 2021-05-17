#### Parser Content
```Java
{
Name = googlecloud-storage-activity
  Vendor = Google
  Product = Google Cloud Platform
  Lms = Direct
  DataType = "cloud-storage-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """googleapis.com""", """"serviceName":"storage""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"callerIp":"({src_ip}[^"]{1,2000})""",
    """"({service}storage.googleapis.com)""",
    """"methodName":"({activity}[^"]{1,2000})""",
    """"principalEmail":"(?:({user_email}[^"@]{1,2000}?@({email_domain}[^"@]{1,2000}))|({user}[^"]{1,2000}))"""",
    """"callerSuppliedUserAgent":"({user_agent}[^"]{1,2000})""",
    """"resource".+?location":"({region}[^"]{1,2000})""",
    """policyDelta.+?"role":"roles\/({role}[^"\\\/]{1,2000})""",
    """status.+?"code":\d{1,100}
```