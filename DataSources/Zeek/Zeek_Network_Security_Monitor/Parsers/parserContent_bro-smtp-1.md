#### Parser Content
```Java
{
Name = bro-smtp-1
  Product = Zeek Network Security Monitor
  DataType = "dlp-email-alert"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"mailfrom""", """"rcptto""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"helo":\s{0,100}"({helo}[^"]+)""",
    """"mailfrom":\s{0,100}"({sender}[^"@]+@({exter_domain_sender}[^"@]+))""",
    """"rcptto":\[({recipients}"({recipient}[^",@]+@({exter_domain_recipient}[^"@,]+))".*?)\]""",
    """"subject":\s{0,100}"({subject}[^"]+)""",
    """"user_agent":\s{0,100}"({user_agent}[^"]+)""",
  ]
}
json-bro-activity = {
  Vendor = Zeek
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]+@\s{0,100})?({host}\S+)""",
    """"ts\\?"{1,20}:[\[\\]*"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})"""
    #""""ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"]+)""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"{1,20}:({dest_port}\d{1,100})""",
    """"proto\\?"{1,20}:\\?"{1,20}({protocol}[^"]+)""",
  ]

```