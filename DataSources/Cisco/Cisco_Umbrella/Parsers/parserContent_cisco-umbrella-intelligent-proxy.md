#### Parser Content
```Java
{
Name = cisco-umbrella-intelligent-proxy
 Product = Cisco Umbrella
 Vendor = Cisco
 Lms = Direct
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
 DataType = "web-activity"
 Conditions = [ """"Type":"UmbrellaIntelligentProxyLogs""", """Verdict_s""", """TenantId""", """statusCode_s""" ]
 Fields = [
   """exabeam_host=([^=]+@\s*)?({host}\S+)""",
   """TimeGenerated"+:"+({time}[^"]+)""",
   """"Computer"+:"+({host}[^"]+)?"+,""",
   """"Referer_s"+:"+({referrer}[^"]+)?"+,""",
   """"userAgent_s"+:"+({user_agent}[^"]+)?"+,""",
   """"Verdict_s"+:"+({action}[^"]+)?"+,""",
   """"Categories_s"+:"+({category}[^,"]+)?"+,""",
   """"Categories_s"+:"+({categories}[^"]+)?"+,""",
   """"responseSize_s"+:"+({bytes_out}[^"]+)?"+,""",
   """"requestSize_s"+:"+({bytes_in}[^"]+)?"+,""",
   """"statusCode_s"+:"+({result_code}[^"]+)?"+,""",
   """"ContentType_s"+:"+({mime}[^"]+)?"+,""",
   """"URL_s"+:"+({full_url}[^"]+)?"+,""",
   """"ExternalIP_s"+:"+({dest_ip}[^"]+)?"+,""",
   """"InternalIP_s"+:"+({src_ip}[^"]+)?"+,"""
   """URL_s"+:"+\s*[^"]+?({uri_query}\?[^\s"]+)""",
   """URL_s"+:"+\s*(?:-|\w+:\/+)({web_domain}[^\s\/"]+)""",
   """URL_s"+:"+([^.\s"]+?.)({top_domain}[^\.]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
   """"+URL_s"+:"+.[^"]+?:\/*([^\/"]+)\/({uri_path}[^\s"]+)"""
   ]
}
```