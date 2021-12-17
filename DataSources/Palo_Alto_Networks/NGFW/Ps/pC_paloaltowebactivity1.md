#### Parser Content
```Java
{
Name = paloalto-web-activity-1
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"LogType":"THREAT"""", """"HTTPMethod":""", """"URL":""", """"Subtype":"url"""", """"Application":"web-browsing"""" ]
  Fields = [
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)"""",
    """"host":"({host}[^"]{1,2000})"""",
    """"SourceUser":"({user_email}[^\@]{1,2000}\@[^"]{1,2000})"""",
    """"SourceAddress":"({src_ip}[A-Fa-f\d\.:]{1,2000})"""",
    """"SourcePort":({src_port}\d{1,100}),"""",
    """"DestinationAddress":"({dest_ip}[A-Fa-f\d\.:]{1,2000})"""",
    """"DestinationPort":({dest_port}\d{1,100}),"""",
    """"HTTPMethod":"({method}[^"]{1,2000})"""",
    """"Action":"({action}[^"]{1,2000})"""",
    """"URL":"({full_url}({uri_path}[^?"]{1,2000})\??({uri_query}[^"]{1,2000})?)""",
    """"Referer":"({referer}[^"]{1,2000})"""",
    """"Protocol":"({protocol}[^"]{1,2000})"""",
    """"UserAgent":"({user_agent}[^"]{1,2000}?)\s{0,100}"""",
    """"URLCategoryList":"({categories}[^"]{1,2000})"""",
    """"URLCategory":"({category}[^"]{1,2000})"""",
    """"ContentType":"({mime}[^"]{1,2000})"""",
    """"URL":"({web_domain}[^\/]{0,2000}?({top_domain}[^\.]{1,2000}\.(com|net|ms|app|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|pub||club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|co\.uk|to)))\/"""
  ]


}
```