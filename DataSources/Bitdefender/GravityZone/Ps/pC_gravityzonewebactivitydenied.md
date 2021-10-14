#### Parser Content
```Java
{
Name = gravityzone-web-activity-denied
  Vendor = Bitdefender
  Product = GravityZone
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """gravityzone:""", """"status":"uc_site_blocked"""" ]
  Fields = [
    """"last_blocked":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"user":\{[^\}]{0,2000}?"name":"(({user_email}[^"@]{1,2000}@[^"@]{1,2000})|({user}[^"]{1,2000}))"""",
    """"computer_name":"({host}[^"]{1,2000})""",
    """"url":"({full_url}({web_domain}[^"\\\/:]{1,2000})(:({dest_port}\d{1,100}))?({uri_path}[\\\/]{1,2000}[^"\?]{0,2000}?)({uri_query}\?[^"]{0,2000})?)"""",
  ]
}
```