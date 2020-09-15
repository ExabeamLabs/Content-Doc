#### Parser Content
```Java
{
Name = exchange-dlp-email-out-2
  Conditions = [ """,SMTP,SEND""", """,Originating,""" ]
  DupFields = [ "recipient->external_address", "external_domain_recipient->external_domain" ]
}
```