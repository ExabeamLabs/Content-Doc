#### Parser Content
```Java
{
Name = avanan-dlp-alert-1
  DataType = "dlp-alert"
  Conditions = [ """"eventtype":"avanan_security_event_dlp"""", """"dlp_detections"""", """"security_event"""", """"severity"""" ]

json-avanan-security-alert = {
  Vendor = Check Point
  Product = Avanan
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """"time":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """"eventtype\\{0,10}":\\{0,10}"({alert_name}[^\\"]{1,2000})""",
    """"severity\\{0,10}":({alert_severity}[^,]{1,2000})""",
    """"entity_info\\{0,10}":\{[^\}]{1,2000}?"entity_id\\{0,10}":\\{0,10}"({alert_id}[^"\\]{1,2000})""",
    """"entity_info\\{0,10}":\{[^\}]{1,2000}?"entity_sub_type\\{0,10}":\\{0,10}"({alert_type}[^"\\]{1,2000})""",
    """"(entity_)?payload\\{0,10}":\{[^\}]{1,2000}?"subject\\{0,10}":\\{0,10}"\s{0,100}({subject}[^"\\]{1,2000}?)\s{0,100}\\{0,10}"""",
    """"subject\\{0,10}":\\{0,10}"\s{0,100}({subject}[^\\"]{1,2000}?)\s{0,100}\\{0,10}"""",
    """"saas_info\\{0,10}":\{[^\}]{1,2000}?"full_name\\{0,10}":\\{0,10}"({user_fullname}[^\\"]{1,2000})\\{0,10}"""",
  //  """"saas_info\\{0,10}":\{[^\}]{1,2000}?"email\\{0,10}":\\{0,10}"({user_email}[^\\"]{1,2000})\\{0,10}"""",
    """"entity\\{0,10}":\{[^\}]{1,2000}"recipients\\{0,10}":\[\\{0,10}({recipients}"({recipient}[^\]]{1,2000})\\?")""",
    """"description_text\\{0,10}":\\{0,10}"({additional_info}[^\[]{1,2000}?)\\{0,10}",""",
    """"is_quarantined\\{0,10}":({outcome}[^,]{1,200})""",
    """sender_client_ip\\{0,10}":\\{0,10}"({src_ip}[A-Fa-f:\d\.]{1,2000})""",
    """attachments\\{0,10}":\[\{[^\}]{1,200}?"name\\{0,10}":\\{0,10}"({attachments}[^"\\]{1,2000})""",
    """file_name\\{0,10}":\\{0,10}"\s{0,100}({file_name}[^\\"]{1,2000}?)\s{0,100}\\{0,10}"""",
    """from_email\\{0,10}":\\{0,10}"({sender}[^\\"]{1,200})""",
    ]

 
}
```