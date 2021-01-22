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
```