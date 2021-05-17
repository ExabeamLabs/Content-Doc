#### Parser Content
```Java
{
Name = symantec-atp-alert
  Vendor = Symantec
  Product = Symantec Advanced Threat Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Symantec|ATPU|""", """|atp_incident|""", """"events":""" ]
  Fields = [
    """\Wdevice_time=({time}\d{1,100}\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """"device_name":"({host}[^"]{1,2000})"""",
    """"events":\[.+?"signature_name":"({alert_name}[^"]{1,2000})".+?\]""",
    """"events":\[.+?"threat":\{.*?"name":"({alert_name}[^"]{1,2000})".*?\}.+?\]""",
    """"rule_name":"({alert_type}[^"]{1,2000})"""",
    """"events":\[.+?"alert":"({alert_type}[^"]{1,2000})".+?\]""",
    """"events":\[.+?"file":\{.*?"md5":"?(?:null|({md5}[^"]{1,2000}))"?.*?\}.+?\]""",
    """"events":\[.+?"file":\{.*?"folder":"({file_parent}[^"]{1,2000})".*?\}.+?\]""",
    """"events":\[.+?"file":\{.*?"name":"({file_name}[^"]{1,2000})".*?\}.+?\]""",
    """"events":\[.+?"email_subject":"({additional_info}[^"]{1,2000})".+?\]""",
    """"events":\[.+?"incident_priority_level":"({alert_severity}[^"]{1,2000})".+?\]""",
    """"events":\[.+?"user_name":"(?:SYSTEM|(A|a)dministrator|({user_fullname}[^\s"]{1,2000}\s{1,100}[^\s"]{1,2000})|({user}[^"]{1,2000}))".+?\]""",
    """"events":\[.+?"sender":\{.*?"email_address":"({user_email}[^"]{1,2000})".*?\}.+?\]""",
    """"events":\[.+?"device_name":"({src_host}[^"]{1,2000})".+?\]""",
    """"events":\[.+?"device_ip":"({src_ip}[^"]{1,2000})".+?\]""",
    """"events":\[.+?"email_action":"({outcome}[^"]{1,2000})".+?\]""",
    """"events":\[.+?"actual_action":"({outcome}[^"]{1,2000})".+?\]""",
    """"events":\[.+?"time":"({time}\d{1,100}\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)".+?\]""",
    """"atp_incident_id":({alert_id}\d{1,100})"""
  ]
  DupFields = ["host->dest_host", "file_name->process_name"]
}
```