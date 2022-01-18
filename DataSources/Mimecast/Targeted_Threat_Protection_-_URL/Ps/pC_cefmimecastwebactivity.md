#### Parser Content
```Java
{
Name = cef-mimecast-web-activity
  Vendor = Mimecast
  Product = Targeted Threat Protection - URL
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """dproc=TTP URL Logs""", """"action":"""" ]
  Fields = [
    """"date":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"userEmailAddress":"({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000})""",
    """"action":"({action}[^"]{1,2000})""",
    """"category":"(Unknown|({category}[^"]{1,2000}))""",
    """"url":"(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?[\\\/]{0,2000}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]{1,2000}))(:({dest_port}\d{1,100}))?({uri_path}\/[^\?",]{0,2000}?)?({uri_query}\?[^"]{0,2000}?)?))\s{0,100}"""",
    """"url":"[^\s"]{0,2000}?({top_domain}[^\\\/\.\s":]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|be|gd|zip|to|live|mp|aws))+)(\/|:|")""",
  ]


}
```