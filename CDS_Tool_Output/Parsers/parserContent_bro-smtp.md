#### Parser Content
```Java
{
Name = bro-smtp-activity-2
  Product = Bro
  DataType = "dlp-email-alert"
  Conditions = [ """protocol""", """"smtp"""", """zeek""", """type""" ]
  Fields = ${BroParserTemplates.bro-activity-1.Fields}[
    ]
}
```