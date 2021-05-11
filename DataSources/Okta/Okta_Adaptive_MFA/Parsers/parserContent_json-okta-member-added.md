#### Parser Content
```Java
{
Name = json-okta-member-added
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = Splunk
  DataType = "member-added"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"credentials":""", """"provider":""", """"type": "ACTIVE_DIRECTORY"""", """"status": "ACTIVE"""" ]  
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
     """"employeeNumber":\s{0,100}"({account_id}[^"]+)"""",
     """"status":\s{0,100}"({event_name}[^"]+)"""",
     """"title":\s{0,100}"({group_name}[^"]+)"""",
     """"department":\s{0,100}"({group_type}[^"]+)"""",
     """"created":\s{0,100}"({time}[^"]+)"""",
     """"displayName"{1,20}:\s{0,100}"{1,20}({domain}[^\s\\"]+)\\+({user}[^\s"]+)"""
     """"samAccountName":\s{0,100}"({user}[^"]+)"""",
     """"email":\s{0,100}"({user_email}[^@"\s]+@({email_domain}[^@"\s]+))""""
  ]
}
```