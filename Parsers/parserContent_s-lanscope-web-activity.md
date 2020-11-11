#### Parser Content
```Java
{
Name = s-lanscope-web-activity
  Vendor = LanScope
  Product = LanScope
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"Web??????????????????"""" ]
  Fields = [
    ""","*(|({host}[^"]+))"*,"*(|({user}[^"]+))"*,"*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"*,"*[^"]*"*,"*(|({activity}[^"]+))"*,("*[^"]*"*,){5}"*(|({window_title}[^"]+))"*,"*(|({full_url}(\w+:\/+)?({web_domain}[^"\/]*?({top_domain}[^"\.\/]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))({uri_path}\/[^"\?]*)?({uri_query}\?[^"]*)?))"*,""""
  ]
}
```