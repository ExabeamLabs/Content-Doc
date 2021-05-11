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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"created_at":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"id":\s{0,100}({alert_id}[^,]+)""",
    """"policy_name":\s{0,100}"({alert_name}[^"]+)"""",
    """"entity_origin_type":\s{0,100}"({alert_type}[^"]+)"""",
    """"severity":\s{0,100}"({alert_severity}[^"]+)"""",
    """"entity_name":\s{0,100}"({target}[^"]+)"""",
    """"entity_owner_name":\s{0,100}"({user_fullname}[^"]+)"""",
    """"entity_owner_email":\s{0,100}"({user_email}[^"]+)"""",
    """"entity_vendor_name":\s{0,100}"({process}[^"]+)"""",
    """"entity_direct_url":\s{0,100}"({full_url}[^"]+({top_domain}[^\\\/:\s.]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))"""",
    """"entity_direct_url":\s{0,100}"({additional_info}[^"]+)"""",
  ]
}
```