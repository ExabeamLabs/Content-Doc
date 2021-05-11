#### Parser Content
```Java
{
Name = s-sep-mobile-alert-1
  Conditions = [ """"type": "Malware"""" , """current_risk_warnings""", """package_name""" ]
  Fields = ${SymantecParserTemplates.s-sep-mobile-alert.Fields}[
    """"email":\s{0,100}"({user_email}[^"]+)",\s{0,100}"name":\s{0,100}"({user_fullname}[^"]+)"""",
    """"severity":\s{0,100}"({alert_severity}[^"]+)",\s{0,100}"id":\s{0,100}({alert_id}\d{1,100})""",
    """"package_name":\s{0,100}"({alert_type}[^"]+)""",
    """"apk_hash":\s{0,100}"({md5}[^"]+)""",
  ]
}
s-sep-mobile-alert = {
  Vendor = Symantec
  Product = Symantec Endpoint Protection Mobile
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}[^"]+)""",
    """"user".+?"email":\s{0,100}(null|"({user_email}[^"]+))""",
    """"user".+?"name":\s{0,100}(null|"({user_fullname}[^"]+))""",
    """"product_name":\s{0,100}"({product_name}[^"]+)""",
    """"os_type":\s{0,100}"({os}[^"]+)""",
    """"device":[^\}]+?"name":\s{0,100}"({src_host}[^"]+?)\s{0,100}"""",
    """"sub_type":\s{0,100}"({alert_name}[^"]+)""",
    """"event_type":\s{0,100}"({additional_info}[^"]+)""",
    """"severity":\s{0,100}"({alert_severity}[^"]+)".+?"id":\s{0,100}({alert_id}\d{1,100})""",
    """"model":\s{0,100}"({device_model}[^"]+)"""",
  ]

```