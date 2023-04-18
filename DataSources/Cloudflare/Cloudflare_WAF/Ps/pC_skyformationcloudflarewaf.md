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
  Conditions = [ """destinationServiceName =Cloudflare""", """ResponseStatus"""", """FirewallMatchesActions""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"EdgeStartTimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """"ClientDeviceType":"({device_type}[^"]{1,2000})""",
    """"ClientCountry":"({src_country}[^"]{1,2000})""",
    """"ClientIP":"(?:["]{1,2000}|({src_ip}[A-Fa-f:\d.]{1,2000}))""",
    """"ClientSrcPort":({src_port}\d{1,100})""",
    """"ClientRequestUserAgent":"({user_agent}[^"]{1,2000})""",
    """"ClientRequestBytes":({bytes_in}\d{1,100})""",
    """"EdgeResponseBytes":({bytes_out}\d{1,100})""",
    """"EdgeResponseStatus":({result_code}({edge_response_status}\d\d\d))"""
    """"OriginResponseStatus":({result_code}({origin_response_status}\d\d\d))"""
    """"EdgeServerIP":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"OriginIP":"({dest_ip}[A-Fa-f:\d.]{1,2000})"{0,20}.*OriginResponseBytes":({bytes_out}\d{1,100})""",
    """"OriginIP":"(?:["]{1,2000}|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """"ClientRequestMethod":"({method}[^"]{1,2000})""",
    """"FirewallMatchesActions[":\[]{1,2000}(?:["\]]{1,2000}|({action}[^,"]{1,2000}))""",
    """"ClientRequestHost":"({web_domain}[^"]{1,2000})""",
    """"ClientRequestURI":"({uri_query}[^"\s]{1,2000})""",
    """"ClientRequestPath":"({uri_path}[^"]{1,2000})""",
    """"ClientRequestProtocol":"({protocol}[^"]{1,2000})""",
    """"SecurityLevel":"({alert_severity}[^"]{1,2000})""",
 ]


}
```