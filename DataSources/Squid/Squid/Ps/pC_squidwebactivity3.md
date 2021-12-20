#### Parser Content
```Java
{
Name = squid-web-activity-3
  Vendor = Squid
  Product = Squid
  Lms = Direct
  DataType = "web-activity"
  TimeFormat ="epoch"
  Conditions = [ """ (squid): """ ]
  Fields = [
    """({host}\S+)\s\(squid\):\s{1,100}({time}[^\.]{1,2000})[\.\d]{1,2000}\s{1,100}\d{1,100}\s({src_ip}[\da-fA-F\.:]{1,2000})\s(\w+\/)?({result_code}\d{1,100})\s({bytes_out}\d{1,100})\s(({method}GET|CONNECT|HEAD|POST|PUT|DELETE|OPTIONS|TRACE)|\S+)\s(error:invalid-request|((({full_url}[^:]{1,2000}:\/\/(({web_domain}[^:\s]{1,2000})?(:({dest_port}\d{1,100}))|[^\s]{1,2000}))?))|(({=web_domain}[^:\s]{1,2000})?(:({=dest_port}\d{1,100})))|({uri_path}[^\s]{1,2000}?)({uri_query}\?[^\s]{1,2000})?)\s(-|({user}\S+))\s(\S+\/)?(-|({dest_ip}[\da-fA-F\.:]{1,2000}))\s(-|({mime}[^\s$]{1,2000}))\s{0,20}$"""
  ]


}
```