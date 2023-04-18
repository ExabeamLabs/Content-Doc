#### Parser Content
```Java
{
Name = cef-okta-member-added
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = Direct
  DataType = "member-added"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"eventType":"group.user_membership.add"""", """"Add user to group membership"""", """"actor":""", """"alternateId":"""" ]
  Fields=[
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S{1,2000})""",
    """"published":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)""",
    """"actor":\{[^\}]{0,2000}?"type":"User","alternateId":"(({user_email}[^@"]{1,2000}@[^"]{1,2000})|({user}[^"]{1,2000}))"""",
    """"actor":\{[^\}]{0,2000}?"type":"User"[^\}]{0,2000}?"displayName":"({user_fullname}({user_firstname}[^"]{1,2000}?)\s({user_lastname}[^"\s]{1,2000}))"""",
    """"type":"UserGroup"[^\}]{0,2000}?"displayName":"({group_name}[^"]{1,2000})"""",
    """"target":\[[^\]]{0,2000}?"type":"User","alternateId":"({account_id}[^"]{1,2000})"""",
    """"target":\[[^\]]{0,2000}?"type":"User","alternateId":"(({target_user_email}[^@"]{1,2000}@[^"]{1,2000})|({target_user}[^"]{1,2000}))"""",
    """"ip":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """"outcome":\{"result":"({outcome}[^"]{1,2000})""""
  ]
  DupFields = [ "outcome->result" ]


}
```