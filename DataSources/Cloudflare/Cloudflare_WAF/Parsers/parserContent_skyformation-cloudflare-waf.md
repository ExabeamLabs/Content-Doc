#### Parser Content
```Java
{
Name = skyformation-cloudflare-waf
  Vendor = Cloudflare
  Product = Cloudflare WAF
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|Skyformation|""", """ResponseStatus"""", """FirewallMatchesActions""", """destinationServiceName=Custom Application""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"EdgeStartTimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """"ClientDeviceType":"({device_type}[^"]+)""",
    """"ClientCountry":"({src_country}[^"]+)""",
    """"ClientIP":"(?:["]+|({src_ip}[A-Fa-f:\d.]+))""",
    """"ClientSrcPort":({src_port}\d{1,100})""",
    """"ClientRequestUserAgent":"({user_agent}[^"]+)""",
    """"ClientRequestBytes":({bytes_in}\d{1,100})""",
    """"EdgeResponseBytes":({bytes_out}\d{1,100})""",
    """"EdgeResponseStatus":({result_code}({edge_response_status}\d\d\d))"""
    """"OriginResponseStatus":({result_code}({origin_response_status}\d\d\d))"""
    """"EdgeServerIP":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"OriginIP":"({dest_ip}[A-Fa-f:\d.]+)"{0,20}.*OriginResponseBytes":({bytes_out}\d{1,100})""",
    """"OriginIP":"(?:["]+|({dest_ip}[A-Fa-f:\d.]+))""",
    """"ClientRequestMethod":"({method}[^"]+)""",
    """"FirewallMatchesActions[":\[]+(?:["\]]+|({action}[^,"]+))""",
    """"ClientRequestHost":"({web_domain}[^"]+)""",
    """"ClientRequestURI":"({uri_query}[^"\s]+)""",
    """"ClientRequestPath":"({uri_path}[^"]+)""",
    """"ClientRequestProtocol":"({protocol}[^"]+)""",
    """"SecurityLevel":"({alert_severity}[^"]+)""",
    """"ClientRequestUserAgent[":]+.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)(.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))?"""
 ]
}
```