#### Parser Content
```Java
{
Name = fireeye-dlp-email
  Vendor = FireEye
  Product = FireEye Email Threat Prevention (ETP)
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"alert_type":""", """"malware_md5":"""", """"rcpt_to":"""", """"mail_from":"""", """"subject":"""", """FireEyeETP""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100})""",
    """"alert_type":\[?"({alert_type}[^"]{1,2000})""",
    """"product":"({alert_name}[^"]{1,2000})""",
    """"malware_md5":"({md5}[^"]{1,2000})""",
    """"email":\{[^\}]{0,2000}?"status":"({outcome}[^"]{1,2000})""",
    """"source_ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"rcpt_to":"({recipients}({recipient}[^"\s@;,]{1,2000}@[^"\s@;,]{1,2000})[^"]{0,2000})""",
    """"mail_from":"({sender}[^"\s@;,]{1,2000}@[^"\s@;,]{1,2000})""",
    """"subject":"({subject}[^"]{1,2000})""",
    """"attachment":"({attachments}({attachment}[^",]{1,2000})[^"]{0,2000})""",
    """"last_malware":"({malware_name}[^"]{1,2000})""",
    """"id":"({alert_id}[^"]{1,2000})""",
  ]


}
```