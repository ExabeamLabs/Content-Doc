#### Parser Content
```Java
{
Name = ironport-proxy-1
  Product = IronPort Web Security
  TimeFormat = "dd/MM/yyyy:HH:mm:ss Z"
  Conditions = [ """IronPort-Web:""", """ TCP_""" ]
  Fields = ${IronPortParserTemplates.ironport-proxy.Fields} [
    """IronPort-Web:.+?({time}\d\d\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d{1,100})"\s\d{1,100}\s"({user_agent}[^"]{1,2000})""",
  ]

ironport-proxy = {
  Vendor = Cisco
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  Fields = [
    """(IronPort-Web|LogRythm):.+?({time}\d{1,100}).+?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s({proxy_action}[^\/]{1,2000})\/({result_code}\d{1,100})\s\d{1,100}\s({method}\S+)\s(-|(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d{1,100}))?)|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?({web_domain}[^\\\/\s:,"]{1,2000})(:\d{1,100})?({uri_path}\/[^\s\?",]{0,2000})?({uri_query}\?[^"\s]{0,2000})?))\s(-|"{0,20}(\w+\\({user}[^@\\\s",]{1,2000})[^\s"]{0,2000}"{0,20}))\s(\w+\/)?(-|({=web_domain}\S+))\s(-|({mime}[^\s]{1,2000}))\s.+?<(-|({category}[^,>]{1,2000}))"""
  
}
```