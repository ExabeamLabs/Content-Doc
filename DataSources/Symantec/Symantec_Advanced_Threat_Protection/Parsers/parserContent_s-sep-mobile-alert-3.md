#### Parser Content
```Java
{
Name = s-sep-mobile-alert-3
  Conditions = [ """"type":"Network"""" , """current_risk_warnings""", """health_status""", """mdm_status""", """"current_health_warnings""" ]
  Fields = ${SymantecParserTemplates.s-sep-mobile-alert.Fields}[
    """"severity":\s{0,100}"({alert_severity}[^"]+)".+?"id":\s{0,100}({alert_id}\d{1,100})""",
    """"type":\s{0,100}"({alert_type}[^"]+)""",
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