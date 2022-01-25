#### Parser Content
```Java
{
Name = cef-cisco-dns-response-sk4-4
  Conditions = ["""CEF:0|Skyformation""", """"QueryType_s":"""", """"Action_s":"Proxied""""]

cef-cisco-dns-response-sk4-template {
  Vendor = Cisco
  Product = Cisco Umbrella
  Lms = Splunk
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """"ResponseCode_s":"({dns_response_code}[^"]{1,2000})"""
    """"Domain_s":"({query}[^"]{1,2000})"""
    """"Domain_s":"({query}[^"]{1,2000}\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))"""
    """"domain":"({query}[^"]{1,2000}\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))"""
    """"Action_s":"({outcome}[^"]{1,2000})"""
    """"QueryType_s":"({query_type}[^"]{1,2000})"""
    """"Categories_s":"({categories}[^"]{1,2000})"""
    """"InternalIP_s":"({dest_ip}[^"]{1,2000})"""
    """"Identites_s":"([\w\s\.]{1,2000},)?(({user_fullname}\w+\s{1,100}\w+[^",]{1,2000}?) \(({user_email}[^\)@]{1,2000}?@[^\)]{1,2000}?)\))?(,({dest_host}[^\(\)"\s]{1,2000}))?"""
  
}
```