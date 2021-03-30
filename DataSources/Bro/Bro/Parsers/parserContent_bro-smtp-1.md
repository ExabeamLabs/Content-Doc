#### Parser Content
```Java
{
Name = bro-smtp-1
  DataType = "dlp-email-alert"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"mailfrom""", """"rcptto""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"helo":\s*"({helo}[^"]+)""",
    """"mailfrom":\s*"({sender}[^"@]+@({exter_domain_sender}[^"@]+))""",
    """"rcptto":\[({recipients}"({recipient}[^",@]+@({exter_domain_recipient}[^"@,]+))".*?)\]""",
    """"subject":\s*"({subject}[^"]+)""",
    """"user_agent":\s*"({user_agent}[^"]+)""",
  ]
}
json-bro-activity = {
  Vendor = Bro
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"+:\\?"+({conn_id}[^"]+)""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}\d+)""",
    """"proto\\?"+:\\?"+({protocol}[^"]+)""",
  ]

```