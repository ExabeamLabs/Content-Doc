#### Parser Content
```Java
{
Name = exchange-dlp-email-in-3
  Conditions = [ """,SMTP,SENDEXTERNAL,""", """,Incoming,""" ]
  DupFields = [ "sender->external_address", "external_domain_sender->external_domain" ]
}
```