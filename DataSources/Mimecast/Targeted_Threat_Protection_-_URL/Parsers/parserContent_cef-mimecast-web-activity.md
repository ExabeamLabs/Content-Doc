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
    """"userEmailAddress":"({user_email}[^\s@"]+@[^\s@"]+)""",
    """"action":"({action}[^"]+)""",
    """"category":"(Unknown|({category}[^"]+))""",
    """"url":"(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?[\\\/]*(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]+))(:({dest_port}\d{1,100}))?({uri_path}\/[^\?",]*?)?({uri_query}\?[^"]*?)?))\s{0,100}"""",
    """"url":"[^\s"]*?({top_domain}[^\\\/\.\s":]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|be|gd|zip|to|live|mp|aws))+)(\/|:|")""",
  ]
}
```