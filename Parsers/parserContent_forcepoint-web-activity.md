#### Parser Content
```Java
{
Name = forcepoint-web-activity
  Product = Websense Secure Gateway
  DataType = "web-activity"
  Conditions = [ """CEF:""", """|FORCEPOINT|""", """|HTTP_URL-Logged|""" ]
  Fields = ${ForcepointParserTemplates.forcepoint-template.Fields} [
    """\Wmsg=(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\\\/\s:,"]+))?(:({dest_port}\d+))?({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?))"""
    ]
}
```