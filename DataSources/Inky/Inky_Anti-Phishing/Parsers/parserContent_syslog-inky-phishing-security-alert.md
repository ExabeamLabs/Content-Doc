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
     """"reason_htmls":\s{0,100}\["({additional_info}[^\]]+?)(",|"\])""",
     """"reason_titles":\s{0,100}\["({alert_name}[^"]+)""",
     """"result_bucket":\s{0,100}"({alert_severity}[^"]+)"""",
     """"short_reasons":\s{0,100}\s{0,100}\["({alert_type}[^"]+)""",
     """"client_ip":\s{0,100}"({dest_ip}[A-Fa-f:\d.]+)"""",
     """\d\d:\d\d:\d\d\.\S+\s({host}[^\s]+)\s{1,100}inky""",
     """"rcpt_to_addresses":\s{0,100}\["({recipient}[^"@]+@[^"]+)"""",
     """"mail_from":\s{0,100}"<?({sender}[^"@]+@[^"]+)>?"""",
     """"sender_IP":\s{0,100}"({src_ip}[A-Fa-f:\d.]+)"""",
     """"subject":\s{0,100}"({subject}[^"]+?)\s{0,100}"""",
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)\s\S+\s{1,100}inky""",
     """"original_url":\s{0,100}"({malware_url}[^"]+)"""",
     """"tracking_id":({alert_id}\d{1,100})""",
     """"threat_level":({threat_level}\d{1,100})"""
  ]
  DupFields = ["recipient->user_email"]
}
```