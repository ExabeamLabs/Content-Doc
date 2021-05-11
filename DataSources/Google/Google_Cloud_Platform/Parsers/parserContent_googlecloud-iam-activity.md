#### Parser Content
```Java
{
Name = googlecloud-iam-activity
  Vendor = Google
  Product = Google Cloud Platform
  Lms = Direct
  DataType = "cloud-admin-activity"
  TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
  Conditions = [ """googleapis.com""",       """"serviceName":"iam"""    ]
  Fields = [
     """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
     """"timestamp":({time}\d{1,100})""",
     """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
     """"callerIp":"({src_ip}[^"]+)""",
     """"({service}iam.googleapis.com)""",
     """"methodName":"({activity}[^"]+)""",
     """"principalEmail":"(?:({user_email}[^"@]+?@({email_domain}[^"@]+))|({user}[^"]+))"""",
     """"callerSuppliedUserAgent":"({user_agent}[^"]+)""",
     """"resource".+?location":"({region}[^"]+)""",
     """policyDelta.+?"role":"roles\/({role}[^"\\\/]+)""",
     """status.+?"code":\d{1,100}
```