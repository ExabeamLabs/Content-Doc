#### Parser Content
```Java
{
Name = okta-member-removed
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = Direct
  DataType = "member-removed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Remove user from group membership""", """group.user_membership.remove""", """"actor":""", """"type":""", """destinationServiceName =Okta""" ]
  Fields = [
    """"published":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)"""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"ipAddress":"({src_ip}[a-fA-F\d:.]{1,2000})""",
    """"actor":\{[^\}]{1,2000}?"type":"User","alternateId":"({user_email}[^@"]{1,2000}@[^"]{1,2000})"""",
    """"actor":\{[^\}]{1,2000}?"type":"User"[^\}]{1,2000}?"displayName":"({user_fullname}({user_firstname}[^\s"]{1,2000})\s({user_lastname}[^"]{1,2000}))"""",
    """"target":\[[^\]]{1,2000}?"type":"+User","alternateId":"({target_user}[^"]{1,2000})"""",
    """"target":\[[^\]]{1,2000}?"type":"({object_type}[^"]{1,2000})"""",
    """"type":"UserGroup"[^\}]{1,2000}?"displayName":"({group_name}[^"]{1,2000})"""",
    """displayMessage":"({event_name}[^"]{1,2000})"""",
    """"eventType":"({event_code}[^"]{1,2000})"""",
    """"result":"({outcome}[^"]{1,2000})""""
  ]
  DupFields = [ "target_user->object" ]


}
```