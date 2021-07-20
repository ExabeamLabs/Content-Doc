#### Parser Content
```Java
{
Name = cef-symantec-atp-alert
  Vendor = Symantec
  Product = Symantec Advanced Threat Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Symantec|Symantec Advanced Threat Protection|""", """"device_time":""" ]
  Fields = [
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})""",
    """"device_time":"({time}\d{1,100}\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"device_name":"({src_host}[^"]{1,2000})"""",
    """"device_domain":"({domain}[^"]{1,2000})"""",
    """"file":\{.*?"md5":"?(?:null|({md5}[^"]{1,2000}))"""",
    """"file":\{.*?"path":"({file_path}({file_parent}[^"]{0,2000}?)({file_name}[^"\\\/]{1,2000}?)(\.({file_ext}[^"\\\/.]{1,2000}))?)"""",
    """"user_name":"(?:SYSTEM|(A|a)dministrator|({user_fullname}[^\s"]{1,2000}\s{1,100}[^\s"]{1,2000})|({user}[^"]{1,2000}))".+?\]""",
    """"device_os_name":"({os}[^"]{1,2000})"""",
    """"event_id":({alert_id}\d{1,100})""",
    """"severity_id":({alert_severity}\d{1,100})""",
    """"device_ip":"({src_ip}[^"]{1,2000})"""",
    """"status_detail":"({alert_type}[^"]{1,2000})"""",
    """"product_name":"({product_name}[^"]{1,2000})"""",
    """"message":"({additional_info}[^"]{1,2000})"""",
  ]
  DupFields = ["host->dest_host", "file_name->process_name"]
}
```