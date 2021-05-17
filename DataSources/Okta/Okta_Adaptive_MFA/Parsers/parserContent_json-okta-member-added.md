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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """"employeeNumber":\s{0,100}"({account_id}[^"]{1,2000})"""",
     """"status":\s{0,100}"({event_name}[^"]{1,2000})"""",
     """"title":\s{0,100}"({group_name}[^"]{1,2000})"""",
     """"department":\s{0,100}"({group_type}[^"]{1,2000})"""",
     """"created":\s{0,100}"({time}[^"]{1,2000})"""",
     """"displayName"{1,20}:\s{0,100}"{1,20}({domain}[^\s\\"]{1,2000})\\+({user}[^\s"]{1,2000})"""
     """"samAccountName":\s{0,100}"({user}[^"]{1,2000})"""",
     """"email":\s{0,100}"({user_email}[^@"\s]{1,2000}@({email_domain}[^@"\s]{1,2000}))""""
  ]
}
```