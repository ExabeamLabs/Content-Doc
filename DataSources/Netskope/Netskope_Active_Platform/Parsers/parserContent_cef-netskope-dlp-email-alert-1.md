#### Parser Content
```Java
{
Name = cef-netskope-dlp-email-alert-1
  DataType = "dlp-email-alert"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"object_type":"Mail"""", """"activity":"Send"""" ]
  Fields = ${NetskopeParserTemplates.cef-netskope-activity.Fields} [
    """"from_user":"({sender}[^"\s@]+@[^"\s@]+)""",
    """"to_user":"({recipients}({recipient}[^"\s@;,]+@({external_domain}[^"\s@,]+))[^"]*)""",
  ]
  DupFields = [ "object->file_name", "recipient->external_address" ]
}
```