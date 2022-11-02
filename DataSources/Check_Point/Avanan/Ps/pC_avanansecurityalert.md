#### Parser Content
```Java
{
Name = avanan-security-alert
  DataType = "alert"
  Conditions = [ """"avanan_security_event_malware\"""", """"eventtype\"""", """"security_event\"""", """"severity\"""" ]

json-avanan-security-alert = {
  Vendor = Check Point
  Product = Avanan
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """"time":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """"eventtype\\":\\"({alert_name}[^\\"]{1,2000})""",
    """"severity\\":({alert_severity}[^,]{1,2000})""",
    """"entity_info\\":\{[^\}]{1,2000}?"entity_id\\":\\"({alert_id}[^"\\]{1,2000})""",
    """"entity_info\\":\{[^\}]{1,2000}?"entity_sub_type\\":\\"({alert_type}[^"\\]{1,2000})""",
    """"(entity_)?payload\\":\{[^\}]{1,2000}?"subject\\":\\"\s{0,100}({subject}[^"\\]{1,2000}?)\s{0,100}\\"""",
    """"subject\\":\\"\s{0,100}({subject}[^\\"]{1,2000}?)\s{0,100}\\"""",
    """"saas_info\\":\{[^\}]{1,2000}?"full_name\\":\\"({user_fullname}[^\\"]{1,2000})\\"""",
  //  """"saas_info\\":\{[^\}]{1,2000}?"email\\":\\"({user_email}[^\\"]{1,2000})\\"""",
    """"entity\\":\{[^\}]{1,2000}"recipients\\":\[\\({recipients}"({recipient}[^\]]{1,2000})\\?")""",
    """"description_text\\?":\\"({additional_info}[^\\"]{1,2000}?)\\"""",
    """"is_quarantined\\":({outcome}[^,]{1,200})""",
    """sender_client_ip\\":\\"({src_ip}[A-Fa-f:\d\.]{1,2000})""",
    """attachments\\":\[\{[^\}]{1,200}?"name\\":\\"({attachments}[^"\\]{1,2000})""",
    """file_name\\":\\"\s{0,100}({file_name}[^\\"]{1,2000}?)\s{0,100}\\"""",
    """from_email\\":\\"({sender}[^\\"]{1,200})""",
    ]

 
}
```