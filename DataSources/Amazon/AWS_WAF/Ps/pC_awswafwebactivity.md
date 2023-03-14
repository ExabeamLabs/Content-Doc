#### Parser Content
```Java
{
Name = aws-waf-web-activity
  Vendor = Amazon
  Product = AWS WAF
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ """"action":"""", """"httpMethod":"""", """"uri":"""", """aws:waf""", """"httpRequest":""", """"name":"user-agent"""" ]
  Fields = [
    """"timestamp":({time}\d{1,13}),""",
    """\d\d\s\d\d:\d\d:\d\d\s({host}[\w\-\.]{1,2000})""",
    """"clientIp":"({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """"name":"user-agent","value":"({user_agent}[^"]{1,2000})"""",
    """"name":"host","value":"({web_domain}[^"]{1,2000})"""",
    """"uri":"({uri_path}[^"]{1,2000})"""",
    """"args":"({uri_query}[^"]{1,2000})"""",
    """"action":"({action}[^"]{1,2000})"""",
    """"httpVersion":"({protocol}[^"]{1,2000})"""",
    """"httpMethod":"({method}[^"]{1,2000})"""",
    """"name":"accept","value":"({mime}[^"]{1,2000})"""",
    """"AccountName":"({user}[^"]{1,2000})""""
  ]


}
```