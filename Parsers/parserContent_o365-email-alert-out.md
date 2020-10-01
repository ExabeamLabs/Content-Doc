#### Parser Content
```Java
{
Name = O365-email-alert-out
  Conditions = [ """"activity_type":"Send"""" ]
  Fields = ${MSParserTemplates.O365-email-alert.Fields} [
    """"user":"({sender}[^"\s@]+@[^"\s@]+)""",
    """"user":"({external_address}[^"\s@;,]+@({external_domain}[^"\s@;,]+))""",
  ]
}
```