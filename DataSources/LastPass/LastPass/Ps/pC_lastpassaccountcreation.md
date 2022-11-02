#### Parser Content
```Java
{
Name = lastpass-account-creation
  Vendor = LastPass
  Product = LastPass
  DataType = "account-creation"
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """event-name":"audit-event""", """Action":"Created LastPass Account""", """application-action":"Created LastPass Account""" ]
  Fields = [
    """"time":"({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"""",
    """\d\d\dZ\s({host}[\w\-.]{1,2000})""",
    """"Username":"({user_email}[^@"]{1,2000}@[^"\.]{1,2000}\.[^"]{1,2000})"""",
    """"src-ip":"({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """"application-action":"({activity}[^"]{1,2000})""",
    """"event-name":"({event_name}[^"]{1,2000})""""
   ]


}
```