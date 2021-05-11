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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"callerIp":"({src_ip}[^"]+)""",
    """"({service}storage.googleapis.com)""",
    """"methodName":"({activity}[^"]+)""",
    """"principalEmail":"(?:({user_email}[^"@]+?@({email_domain}[^"@]+))|({user}[^"]+))"""",
    """"callerSuppliedUserAgent":"({user_agent}[^"]+)""",
    """"resource".+?location":"({region}[^"]+)""",
    """policyDelta.+?"role":"roles\/({role}[^"\\\/]+)""",
    """status.+?"code":\d{1,100}
```