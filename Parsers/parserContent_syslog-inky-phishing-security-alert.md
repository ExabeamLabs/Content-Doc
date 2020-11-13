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
     """"reason_htmls":\s*\["({additional_info}[^\]]+?)(",|"\])""",
     """"reason_titles":\s*\["({alert_name}[^"]+)""",
     """"result_bucket":\s*"({alert_severity}[^"]+)"""",
     """"short_reasons":\s*\s*\["({alert_type}[^"]+)""",
     """"client_ip":\s*"({dest_ip}[A-Fa-f:\d.]+)"""",
     """\d\d:\d\d:\d\d\.\S+\s({host}[^\s]+)\s+inky""",
     """"rcpt_to_addresses":\s*\["({recipient}[^"@]+@[^"]+)"""",
     """"mail_from":\s*"<?({sender}[^"@]+@[^"]+)>?"""",
     """"sender_IP":\s*"({src_ip}[A-Fa-f:\d.]+)"""",
     """"subject":\s*"({subject}[^"]+?)\s*"""",
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)\s\S+\s+inky""",
     """"original_url":\s*"({malware_url}[^"]+)"""",
     """"tracking_id":({alert_id}\d+)""",
     """"threat_level":({threat_level}\d+)"""
  ]
  DupFields = ["recipient->user_email"]
}
```