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
    """"EdgeStartTimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """({host}[\w\-.]+)\s+Skyformation""",
    """"ClientDeviceType":"({device_type}[^"]+)""",
    """"ClientCountry":"({src_country}[^"]+)""",
    """"ClientIP":"(?:["]+|({src_ip}[A-Fa-f:\d.]+))""",
    """"ClientSrcPort":({src_port}\d+)""",
    """"ClientRequestUserAgent":"({user_agent}[^"]+)""",
    """"ClientRequestBytes":({bytes_in}\d+)""",
    """"EdgeResponseBytes":({bytes_out}\d+)""",
    """"EdgeResponseStatus":({result_code}({edge_response_status}\d\d\d))"""
    """"OriginResponseStatus":({result_code}({origin_response_status}\d\d\d))"""
    """"EdgeServerIP":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"OriginIP":"({dest_ip}[A-Fa-f:\d.]+)"*.*OriginResponseBytes":({bytes_out}\d+)""",
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

{
  Name = tfcs-web-activity
  Vendor = HashiCorp
  Product = Terraform
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """ TFCS_LOG """ ]
  Fields = [
    """\s({host}[\w\-.]+)\s+TFCS_LOG\s+.*?({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+)\s+({src_ip}[A-Fa-f:\d.]+?):({src_port}\d+)\s+({user_email}[^\s@]+@[^\s@]+)\s+({result_code}\d+)\s+({bytes}\d+)\s+({method}\S+)\s+(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?[\\\/]*(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]+))(:({dest_port}\d+))?({uri_path}\/[^\s\?",]*)?({uri_query}\?[^"\s]*)?))\s+({action}[^\s]+)\s""",
    """\s+\d+\s+\d+\s+\S+\s+[^\s]*?({top_domain}[^\\\/\.\s":]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|be|gd|zip|to|live|mp|aws))+)(\/|:|")""",
  ]
  DupFields = [ "action->resource" ]
}

{
  Name = cef-gtb-dlp-alert
  Vendor = GTB
  Product = GTBInspector
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|GTB|GTBInspector|""", """externalId=""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdhost=(|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wcs2=({protocol}[^=]+?)\s+\w+=""",
    """\Wshost=(|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}.+?))(\s+\w+=|\s*$)""",
    """\Wspt=({src_port}\d+)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdvc=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\Wsuser=({user_email}[^=\s]+)""",
    """\Wsuser=[^=]*?<({user_email}[^<]+)>""",
    """\Wcs5=(|({subject}.+?))(\s+\w+=|\s*$)""",
    """CEF[^\|]+?\|GTB\|GTBInspector\|[^\|]+?\|({alert_type}[^\|]+?)\|({alert_name}[^\|]+)\|({alert_severity}\d+)"""
    """\sduser=([\s"]+suser=|[\s"]*({target}.*?)[\s"]*suser=)"""
  ]
}
```