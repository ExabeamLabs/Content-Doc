#### Parser Content
```Java
{
Name = json-cisco-cloudlock-dlp
  Vendor = Cisco
  Product = Cisco CloudLock
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"entity_vendor_name":""", """"entity_owner_email":""", """"ctx_after":""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"created_at":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"id":\s{0,100}({alert_id}[^,]{1,2000})""",
    """"policy_name":\s{0,100}"({alert_name}[^"]{1,2000})"""",
    """"entity_origin_type":\s{0,100}"({alert_type}[^"]{1,2000})"""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})"""",
    """"entity_name":\s{0,100}"({target}[^"]{1,2000})"""",
    """"entity_owner_name":\s{0,100}"({user_fullname}[^"]{1,2000})"""",
    """"entity_owner_email":\s{0,100}"({user_email}[^"]{1,2000})"""",
    """"entity_vendor_name":\s{0,100}"({process}[^"]{1,2000})"""",
    """"entity_direct_url":\s{0,100}"({full_url}[^"]{1,2000}([^\\\/:\s.]{1,2000}))"""",
    """"entity_direct_url":\s{0,100}"({additional_info}[^"]{1,2000})"""",
  ]


}
```