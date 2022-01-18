#### Parser Content
```Java
{
Name = cl-cisco-dns-response-sk4-4
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Lms = Direct
  Conditions = ["""TenantId""", """UmbrellaDNSLogs_CL""", """Identites_s"""]
  Fields=${CiscoParsersTemplates.cef-cisco-dns-response-sk4-template.Fields}[
    """TimeGenerated"{1,20}:"{1,20}({time}[^"]{1,2000})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"Categories_s"{1,20}:"{1,20}({category}[^,"]{1,2000})?"{1,20
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