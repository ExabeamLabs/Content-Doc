#### Parser Content
```Java
{
Name = bro-smtp-1
  Product = Zeek Network Security Monitor
  DataType = "dlp-email-alert"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"mailfrom""", """"rcptto""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"helo":\s{0,100}"({helo}[^"]{1,2000})""",
    """"mailfrom":\s{0,100}"({sender}[^"@]{1,2000}@({exter_domain_sender}[^"@]{1,2000}))""",
    """"rcptto":\[({recipients}"({recipient}[^",@]{1,2000}@({exter_domain_recipient}[^"@,]{1,2000}))".*?)\]""",
    """"subject":\s{0,100}"({subject}[^"]{1,2000})""",
    """"user_agent":\s{0,100}"({user_agent}[^"]{1,2000})""",
  ]
}
json-bro-activity = {
  Vendor = Zeek
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"ts\\?"{1,20}:[\[\\]{0,2000}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})"""
    #""""ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"]{1,2000})""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p\\?"{1,20}:({dest_port}\d{1,100})""",
    """"proto\\?"{1,20}:\\?"{1,20}({protocol}[^"]{1,2000})""",
  ]

```