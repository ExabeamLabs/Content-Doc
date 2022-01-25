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
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """"recipients"{1,20}:\s{0,100}\[([\s\n]{0,2000})?"{1,20}({recipient}[^"\s,@]{1,2000}@({external_domain}[^"\s@,]{1,2000}))""",
     """"sender"{1,20}:\s{0,100}"{1,20}({sender}[^"\s@]{1,2000}@[^"\s@]{1,2000})"""",
     """"requestIp"{1,20}:\s"{1,20}({src_ip}[a-fA-f\d\.:]{1,2000})"""",
     """"policyId"{1,20}:\s{0,100}"{1,20}({alert_id}[^"]{1,2000})"""",
     """"policyType"{1,20}:\s{0,100}"{1,20}({alert_name}[^"]{1,2000})"""",
     """"userAgent"{1,20}:\s{0,100}"{1,20}({user_agent}[^"]{1,2000})"""",
     """"displayName"{1,20}:\s{0,100}"{1,20}\s{0,100}({additional_info}[^"]{1,2000}?)\s{0,100}"""",
     """"type"{1,20}:\s{0,100}"{1,20}({alert_type}[^"]{1,2000})""""
  ]
  DupFields = [ "sender->user_email" ]
}
```