#### Parser Content
```Java
{
Name = s-sep-mobile-alert-3
  Conditions = [ """"type":"Network"""" , """current_risk_warnings""", """health_status""", """mdm_status""", """"current_health_warnings""" ]
  Fields = ${SymantecParserTemplates.s-sep-mobile-alert.Fields}[
    """"severity":\s*"({alert_severity}[^"]+)".+?"id":\s*({alert_id}\d+)""",
    """"type":\s*"({alert_type}[^"]+)""",
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
    """"timestamp":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+[^"]+)""",
    """"user".+?"email":\s*(null|"({user_email}[^"]+))""",
    """"user".+?"name":\s*(null|"({user_fullname}[^"]+))""",
    """"product_name":\s*"({product_name}[^"]+)""",
    """"os_type":\s*"({os}[^"]+)""",
    """"device":[^\}]+?"name":\s*"({src_host}[^"]+?)\s*"""",
    """"sub_type":\s*"({alert_name}[^"]+)""",
    """"event_type":\s*"({additional_info}[^"]+)""",
    """"severity":\s*"({alert_severity}[^"]+)".+?"id":\s*({alert_id}\d+)""",
    """"model":\s*"({device_model}[^"]+)"""",
  ]

```