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
     """"lastModified"{1,20}:\s{0,100}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
     """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
     """"recipients"{1,20}:\s{0,100}\[([\s\n]*)?"{1,20}({recipient}[^"\s,@]+@({external_domain}[^"\s@,]+))""",
     """"sender"{1,20}:\s{0,100}"{1,20}({sender}[^"\s@]+@[^"\s@]+)"""",
     """"requestIp"{1,20}:\s"{1,20}({src_ip}[a-fA-f\d\.:]+)"""",
     """"policyId"{1,20}:\s{0,100}"{1,20}({alert_id}[^"]+)"""",
     """"policyType"{1,20}:\s{0,100}"{1,20}({alert_name}[^"]+)"""",
     """"userAgent"{1,20}:\s{0,100}"{1,20}({user_agent}[^"]+)"""",
     """"displayName"{1,20}:\s{0,100}"{1,20}\s{0,100}({additional_info}[^"]+?)\s{0,100}"""",
     """"type"{1,20}:\s{0,100}"{1,20}({alert_type}[^"]+)""""
  ]
  DupFields = [ "sender->user_email" ]
}
```