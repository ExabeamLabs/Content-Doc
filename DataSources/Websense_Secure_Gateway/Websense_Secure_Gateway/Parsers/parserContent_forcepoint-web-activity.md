#### Parser Content
```Java
{
Name = forcepoint-web-activity
  Product = Websense Secure Gateway
  DataType = "web-activity"
  Conditions = [ """CEF:""", """|FORCEPOINT|""", """|HTTP_URL-Logged|""" ]
  Fields = ${ForcepointParserTemplates.forcepoint-template.Fields} [
    """\Wmsg=(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\\\/\s:,"]{1,2000}))?(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?))"""
    ]
}
```