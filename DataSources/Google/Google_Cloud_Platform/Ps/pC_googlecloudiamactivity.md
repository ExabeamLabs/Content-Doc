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
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """"timestamp":({time}\d{1,100})""",
     """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
     """"callerIp":"({src_ip}[^"]{1,2000})""",
     """"({service}iam.googleapis.com)""",
     """"methodName":"({activity}[^"]{1,2000})""",
     """"principalEmail":"(?:({user_email}[^"@]{1,2000}?@({email_domain}[^"@]{1,2000}))|({user}[^"]{1,2000}))"""",
     """"callerSuppliedUserAgent":"({user_agent}[^"]{1,2000})""",
     """"resource".+?location":"({region}[^"]{1,2000})""",
     """policyDelta.+?"role":"roles\/({role}[^"\\\/]{1,2000})""",
     """status.+?"code":\d{1,100

}
```