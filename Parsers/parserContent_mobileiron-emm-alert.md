#### Parser Content
```Java
{
Name = mobileiron-emm-alert
  Vendor = MobileIron
  Product = MobileIron EMM
  Lms = Direct
  DataType = "alert"
  TimeFormat = "MMM dd',' yyyy',' HH:mm"
  Conditions = [ """cont-2731_custom_conditions""" ]
  Fields = [
    """({time}\w+ \d+\, \d\d\d\d\, \d+:\d+)""",
    """"([^"]+")([^,]*,){2}({alert_severity}[^,]+)""",
    """"([^"]+")([^,]*,){4}({alert_type}[^,]+)""",
    """"([^"]+")([^,]*,){5}({alert_name}[^,]+)""",
    """"([^"]+")([^,]*,){6}({additional_info}[^,]+)""",
    """"([^"]+")([^,]*,){7}({user_fullname}[^,]+)""",
    """"([^"]+")([^,]*,){8}({sensor_id}[^,]+)""",
    """"([^"]+")([^,]*,){13}({host}[^,]+)""",
    """"([^"]+")([^,]*,){14}({src_ip}[^,]+)""",
    """"([^"]+")([^,]*,){15}({malware_url}[^,]+)""",
  ]
}
```