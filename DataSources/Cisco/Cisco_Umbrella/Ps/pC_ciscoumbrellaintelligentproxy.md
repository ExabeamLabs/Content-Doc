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
   """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
   """TimeGenerated"{1,20}:"{1,20}({time}[^"]{1,2000})""",
   """"Computer"{1,20}:"{1,20}({host}[^"]{1,2000})?"{1,20},""",
   """"Referer_s"{1,20}:"{1,20}({referrer}[^"]{1,2000})?"{1,20},""",
   """"userAgent_s"{1,20}:"{1,20}({user_agent}[^"]{1,2000})?"{1,20},""",
   """"Verdict_s"{1,20}:"{1,20}({action}[^"]{1,2000})?"{1,20},""",
   """"Categories_s"{1,20}:"{1,20}({category}[^,"]{1,2000})?"{1,20},""",
   """"Categories_s"{1,20}:"{1,20}({categories}[^"]{1,2000})?"{1,20},""",
   """"responseSize_s"{1,20}:"{1,20}({bytes_out}[^"]{1,2000})?"{1,20},""",
   """"requestSize_s"{1,20}:"{1,20}({bytes_in}[^"]{1,2000})?"{1,20},""",
   """"statusCode_s"{1,20}:"{1,20}({result_code}[^"]{1,2000})?"{1,20},""",
   """"ContentType_s"{1,20}:"{1,20}({mime}[^"]{1,2000})?"{1,20},""",
   """"URL_s"{1,20}:"{1,20}({full_url}[^"]{1,2000})?"{1,20},""",
   """"ExternalIP_s"{1,20}:"{1,20}({dest_ip}[^"]{1,2000})?"{1,20},""",
   """"InternalIP_s"{1,20}:"{1,20}({src_ip}[^"]{1,2000})?"{1,20},"""
   """URL_s"{1,20}:"{1,20}\s{0,100}[^"]{1,2000}?({uri_query}\?[^\s"]{1,2000})""",
   """URL_s"{1,20}:"{1,20}\s{0,100}(?:-|\w+:\/+)({web_domain}[^\s\/"]{1,2000})""",
   """"{1,20}URL_s"{1,20}:"{1,20}.[^"]{1,2000}?:\/*([^\/"]{1,2000})\/({uri_path}[^\s"]{1,2000})"""
   ]
}
```