#### Parser Content
```Java
{
Name = virtru-email-encryption-alert
  Vendor = Virtru
  Product = Virtru
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"accessedBy":""", """"policyType":""", """"forwardLog":""", """"recipients":""", """"sender":""", """virtru""" ]
  Fields = [
     """"lastModified"+:\s*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """"recipients"+:\s*\[([\s\n]*)?"+({recipient}[^"\s,@]+@({external_domain}[^"\s@,]+))""",
     """"sender"+:\s*"+({sender}[^"\s@]+@[^"\s@]+)"""",
     """"requestIp"+:\s"+({src_ip}[a-fA-f\d\.:]+)"""",
     """"policyId"+:\s*"+({alert_id}[^"]+)"""",
     """"policyType"+:\s*"+({alert_name}[^"]+)"""",
     """"userAgent"+:\s*"+({user_agent}[^"]+)"""",
     """"displayName"+:\s*"+\s*({additional_info}[^"]+?)\s*"""",
     """"type"+:\s*"+({alert_type}[^"]+)""""
  ]
  DupFields = [ "sender->user_email" ]
}
```