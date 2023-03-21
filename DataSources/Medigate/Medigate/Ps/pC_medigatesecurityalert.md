#### Parser Content
```Java
{
Name = medigate-security-alert
  Vendor = Medigate
  Product = Medigate
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"device_category":""", """"event_type":""", """"device_type_family":""" ]
  Fields = [
    """\d\d:\d\d:\d\d[\d\.\+:\-]{1,100}\s{1,100}({host}[\w\-\.]{1,2000})\s{0,100}""",
    """"insertion_time":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}\+[\d\:]{1,100})"""",
    """"event_type":\s{0,100}"({alert_name}[^"]{1,2000})"""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})"""",
    """"text":\s{0,100}"({additional_info}[^"]{1,2000})"""",
    """"protocol":\s{0,100}"({protocol}[^"]{1,2000})"""",
    """"ip_proto":\s{0,100}({protocol}\d{1,100})""",
    """"ip":\s{0,100}"({dest_ip}[A-Fa-f\d\.:]{1,2000})",\s{0,100}"human_name"""",
    """"dest":\s{0,100}[^}]{1,2000}"ip":\s{0,100}"({dest_ip}[A-Fa-f\d\.:]{1,2000})""",
    """"src_ip":\s{0,100}"({src_ip}[A-Fa-f\d\.\:]{1,2000})"""",
    """"srcip":\s{0,100}"({src_ip}[A-Fa-f\d\.\:]{1,2000})"""",
    """"device_category":\s{0,100}"({device_category}[^"]{1,2000})"""",
    """"device_type_family":\s{0,100}"({device_type}[^"]{1,2000})"""",
    """"vendor":\s{0,100}"({device_vendor}[^"]{1,2000})"""",
    """"model":\s{0,100}"({device_name}[^"]{1,2000})""""
  ]
  DupFields = ["alert-name->alert-type"]


}
```