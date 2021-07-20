#### Parser Content
```Java
{
Name = akamai-web-activity
  Vendor = Akamai
  Product = Cloud Akamai
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """"message":{"""", """"reqHost":"""", """"status":"""", """"reqPath":"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"start":"({time}\d{1,100})""",
    """"proto":"({protocol}[^"]{1,2000})""",
    """"status":"({result_code}\d{1,100})""",
    """"cliIP":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"reqPort":"({dest_port}\d{1,100})""",
    """"reqHost":"({web_domain}[^"\s]{1,2000})""",
    """"reqHost":"[^"\s]{0,2000}?({top_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """"reqMethod":"({method}[^"]{1,2000})""",
    """"reqPath":"({uri_path}[^"]{1,2000})""",
    """"reqQuery":"({uri_query}[^"]{1,2000})""",
    """"edgeIP":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"bytes":"({bytes}\d{1,100})""",
  ]
}
```