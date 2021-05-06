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
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """"timestamp":({time}\d+)""",
     """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
     """"callerIp":"({src_ip}[^"]+)""",
     """"({service}iam.googleapis.com)""",
     """"methodName":"({activity}[^"]+)""",
     """"principalEmail":"(?:({user_email}[^"@]+?@({email_domain}[^"@]+))|({user}[^"]+))"""",
     """"callerSuppliedUserAgent":"({user_agent}[^"]+)""",
     """"resource".+?location":"({region}[^"]+)""",
     """policyDelta.+?"role":"roles\/({role}[^"\\\/]+)""",
     """status.+?"code":\d+,"message":"({failure_reason}[^"]+)""",
     """"logName":".*\/cloudaudit.googleapis.com\/({log_type}[^"]+)""",
     """"resource"[^=]*?project_id":"({account}[^"]+)""",
     """"resource"[^=]*?"type":"({resource_type}[^"]+)"""
  ]
}
```