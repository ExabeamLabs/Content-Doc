#### Parser Content
```Java
{
Name = exchange-dlp-email-out-4
  Conditions = [ """,ROUTING,DUPLICATEEXPAND,""", """,Originating,""" ]
  DupFields = [ "recipient->external_address", "external_domain_recipient->external_domain" ]
}
```