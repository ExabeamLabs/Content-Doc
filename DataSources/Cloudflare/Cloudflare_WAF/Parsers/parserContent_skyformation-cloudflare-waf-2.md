#### Parser Content
```Java
{
Name = skyformation-cloudflare-waf-2
  Vendor = Cloudflare
  Product = Cloudflare WAF
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Skyformation|""", """destinationServiceName=Cloudflare""", """"clientIP":"""", """"source":""", """"clientRequestHTTPMethodName":"""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s+[^\s]+\s+Skyformation""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"ClientDeviceType":"({device_type}[^"]+)""",
    """"clientCountryName":"({src_country}[^"]+)""",
    """"clientIP":"(?:["]+|({src_ip}[A-Fa-f:\d.]+))""",
    """"userAgent":"({user_agent}[^"]+)""",
    """"edgeResponseStatus":({result_code}({edge_response_status}\d\d\d))""",
    """"originResponseStatus":({result_code}({origin_response_status}\d\d\d))"""
    """"clientRequestHTTPMethodName":"({method}[^"]+)""",
    """"action":"({action}[^"]+)""",
    """"ClientRequestReferer":"({referrer}[^"]+?)",""",
    """"clientRequestHTTPHost":"({web_domain}[^"<,]+)""",
    """"clientRequestHTTPHost"+:"+[^\s"?=]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d+)?)+(?:\s\w+=|\/|))[^"\s:\/]+)""",
    """"clientRequestPath":"({uri_path}[^"]+)""",
    """"clientRequestHTTPProtocol":"({protocol}[^"//]+)""",
    """"userAgent":.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)(.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))?"""
    ]
}
```