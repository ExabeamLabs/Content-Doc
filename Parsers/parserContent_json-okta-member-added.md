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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """"employeeNumber":\s*"({account_id}[^"]+)"""",
     """"status":\s*"({event_name}[^"]+)"""",
     """"title":\s*"({group_name}[^"]+)"""",
     """"department":\s*"({group_type}[^"]+)"""",
     """"created":\s*"({time}[^"]+)"""",
     """"displayName"+:\s*"+({domain}[^\s\\"]+)\\+({user}[^\s"]+)"""
     """"samAccountName":\s*"({user}[^"]+)"""",
     """"email":\s*"({user_email}[^@"\s]+@({email_domain}[^@"\s]+))""""
  ]
}
```