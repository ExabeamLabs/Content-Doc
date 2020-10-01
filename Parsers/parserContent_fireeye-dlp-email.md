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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"timestamp":"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+)""",
    """"alert_type":\[?"({alert_type}[^"]+)""",
    """"product":"({alert_name}[^"]+)""",
    """"malware_md5":"({md5}[^"]+)""",
    """"email":\{[^\}]*?"status":"({outcome}[^"]+)""",
    """"source_ip":"({src_ip}[A-Fa-f:\d.]+)""",
    """"rcpt_to":"({recipients}({recipient}[^"\s@;,]+@({external_domain_recipient}[^"\s@;,]+))[^"]*)""",
    """"mail_from":"({sender}[^"\s@;,]+@({external_domain_sender}[^"\s@;,]+))""",
    """"subject":"({subject}[^"]+)""",
    """"attachment":"({attachments}({attachment}[^",]+)[^"]*)""",
    """"last_malware":"({malware_name}[^"]+)""",
    """"id":"({alert_id}[^"]+)""",
  ]
}
```