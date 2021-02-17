#### Parser Content
```Java
{
Name = googlecloud-cloudresourcemanager-activity
  Vendor = Google
  Product = Google Cloud Platform
  Lms = Direct
  DataType = "cloud-admin-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"protoPayload":""", """googleapis.com""", """"serviceName":"cloudresourcemanager""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"callerIp":"({src_ip}[^"]+)""",
    """"({service}cloudresourcemanager.googleapis.com)""",
    """"methodName":"({activity}[^"]+)""",
    """"principalEmail":"(?:({user_email}[^"@]+?@({email_domain}[^"@]+))|({user}[^"]+))"""",
    """"callerSuppliedUserAgent":"({user_agent}[^"]+)""",
    """"resource".+?location":"({region}[^"]+)""",
    """policyDelta.+?"role":"roles\/({role}[^"\\\/]+)""",
    """status.+?"code":\d+,"message":"({failure_reason}[^"]+)""",
    ]
}
```