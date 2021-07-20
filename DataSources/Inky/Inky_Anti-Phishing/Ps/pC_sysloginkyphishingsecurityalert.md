#### Parser Content
```Java
{
Name = syslog-inky-phishing-security-alert
  Vendor = Inky
  Product = Inky Anti-Phishing
  Lms = Syslog
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ inky """, """"threat_level":2""", """"identifier":"inky-event"""", """"message_id":""" ]
  Fields = [
     """"reason_htmls":\s{0,100}\["({additional_info}[^\]]{1,2000}?)(",|"\])""",
     """"reason_titles":\s{0,100}\["({alert_name}[^"]{1,2000})""",
     """"result_bucket":\s{0,100}"({alert_severity}[^"]{1,2000})"""",
     """"short_reasons":\s{0,100}\s{0,100}\["({alert_type}[^"]{1,2000})""",
     """"client_ip":\s{0,100}"({dest_ip}[A-Fa-f:\d.]{1,2000})"""",
     """\d\d:\d\d:\d\d\.\S+\s({host}[^\s]{1,2000})\s{1,100}inky""",
     """"rcpt_to_addresses":\s{0,100}\["({recipient}[^"@]{1,2000}@[^"]{1,2000})"""",
     """"mail_from":\s{0,100}"<?({sender}[^"@]{1,2000}@[^"]{1,2000})>?"""",
     """"sender_IP":\s{0,100}"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
     """"subject":\s{0,100}"({subject}[^"]{1,2000}?)\s{0,100}"""",
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)\s\S+\s{1,100}inky""",
     """"original_url":\s{0,100}"({malware_url}[^"]{1,2000})"""",
     """"tracking_id":({alert_id}\d{1,100})""",
     """"threat_level":({threat_level}\d{1,100})"""
  ]
  DupFields = ["recipient->user_email"]
}
```