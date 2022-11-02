#### Parser Content
```Java
{
Name = lastpass-account-password-change
  Vendor = LastPass
  Product = LastPass
  DataType = "password-change"
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """event-name":"password-changed""", """Action":"Master Password Changed""", """src-application-name":"LastPass Enterprise""", """"is-successful":true""" ]
  Fields = [
    """"time":"({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"""",
    """\d\d\dZ\s({host}[\w\-.]{1,2000})""",
    """"user-email":"({user_email}[^@"]{1,2000}@[^"\.]{1,2000}\.[^"]{1,2000})"""",
    """"src-ip":"({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """"application-action":"({activity}[^"]{1,2000})""",
    """"event-name":"({event_name}[^"]{1,2000})"""",
    """"app-user-displayname":"({user_fullname}[^"]{1,2000})""""
   ]


}
```