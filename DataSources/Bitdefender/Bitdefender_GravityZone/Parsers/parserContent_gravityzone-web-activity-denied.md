#### Parser Content
```Java
{
Name = gravityzone-web-activity-denied
  Vendor = Bitdefender
  Product = Bitdefender GravityZone
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """gravityzone:""", """"status":"uc_site_blocked"""" ]
  Fields = [
    """"last_blocked":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"user":\{[^\}]*?"name":"(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))"""",
    """"computer_name":"({host}[^"]+)""",
    """"url":"({full_url}({web_domain}[^"\\\/:]+)(:({dest_port}\d{1,100}))?({uri_path}[\\\/]+[^"\?]*?)({uri_query}\?[^"]*)?)"""",
    """"url":"[^"]*?({top_domain}[^:\\\/\.\s"]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(:|[\\\/]|")""",
  ]
}
```