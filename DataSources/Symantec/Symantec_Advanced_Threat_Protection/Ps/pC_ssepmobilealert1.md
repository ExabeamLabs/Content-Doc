#### Parser Content
```Java
{
Name = s-sep-mobile-alert-1
  Conditions = [ """"type": "Malware"""" , """current_risk_warnings""", """package_name""" ]
  Fields = ${SymantecParserTemplates.s-sep-mobile-alert.Fields}[
    """"email":\s{0,100}"({user_email}[^"]{1,2000})",\s{0,100}"name":\s{0,100}"({user_fullname}[^"]{1,2000})"""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})",\s{0,100}"id":\s{0,100}({alert_id}\d{1,100})""",
    """"package_name":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"apk_hash":\s{0,100}"({md5}[^"]{1,2000})""",
  ]
}
s-sep-mobile-alert = {
  Vendor = Symantec
  Product = Symantec Endpoint Protection Mobile
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}[^"]{1,2000})""",
    """"user".+?"email":\s{0,100}(null|"({user_email}[^"]{1,2000}))""",
    """"user".+?"name":\s{0,100}(null|"({user_fullname}[^"]{1,2000}))""",
    """"product_name":\s{0,100}"({product_name}[^"]{1,2000})""",
    """"os_type":\s{0,100}"({os}[^"]{1,2000})""",
    """"device":[^\}]{1,2000}?"name":\s{0,100}"({src_host}[^"]{1,2000}?)\s{0,100}"""",
    """"sub_type":\s{0,100}"({alert_name}[^"]{1,2000})""",
    """"event_type":\s{0,100}"({additional_info}[^"]{1,2000})""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})".+?"id":\s{0,100}({alert_id}\d{1,100})""",
    """"model":\s{0,100}"({device_model}[^"]{1,2000})"""",
  ]
  DupFields = [ "src_host->device_name" ]}
```