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
O365-email-alert = {
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"_time":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}[\+\-]\d{1,100})""",
    """"name":"({subject}[^"]+?)\s{0,100}"""",
    """"activity_type":"({activity}Receive|Send)""",
    """"user":"({user_email}[^"\s@]+@[^"\s@]+)""",
    """"user_name":"({user_fullname}[^"\s]+\s{1,100}[^"]+)""",
    """"message":"({additional_info}.+?)\s{0,100}",""",
    """"(internal|external)_recipients":"({recipients}({recipient}[^"\s@;,]+@[^"\s@;,]+)[^"]*)"""",
    """ from ({sender}[^"\s@]+@[^"\s@]+)""",
  ]

```