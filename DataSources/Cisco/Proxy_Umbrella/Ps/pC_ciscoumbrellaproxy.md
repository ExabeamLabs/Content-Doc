#### Parser Content
```Java
{
Name = cisco-umbrella-proxy
  Vendor = Cisco
  Product = Proxy Umbrella
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """destinationServiceName =Cisco Umbrella """, """dproc=Proxy """, """"url":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\W(destinationServiceName|requestClientApplication)=({app}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=(anonymous|({user}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"contentTpe"{1,20}:"{1,20}({mime}[^",]{1,2000})""",  
    """"externalIp":"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"internalIp":"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"destinationIp"{1,20}:"{1,20}({dest_ip}[^",]{1,2000})"""",
    """"responseSize"{1,20}:"{1,20}({bytes_out}[^",]{1,2000})"""",
    """"requestSize"{1,20}:"{1,20}({bytes_in}[^",]{1,2000})"""", 
    """"statusCode"{1,20}:"{1,20}({result_code}[^",]{1,2000})"""",
    """"timestamp"{1,20}:"{1,20}({time}[^",]{1,2000})"""",
    """"referer"{1,20}:"{1,20}({referrer}[^",]{1,2000})"""",
    """"userAgent"{1,20}:"{1,20}(\s{1,100}|({user_agent}[^"]{1,2000}))"""", 
    """"url"{1,20}:"{1,20}(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]{1,2000}))?(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?))"""",
    """"url"{1,20}:"{1,20}({protocol}http(s)?)""",
    """"sha"{1,20}:"{1,20}({sha}[^",]{1,2000})"""",
    """"categories"{1,20}:\["{1,20}({category}[^",]{1,2000})""",
    """"verdict"{1,20}:"{1,20}({action}[^",]{1,2000})""",
    """"identityType"{1,20}:"{1,20}({identity_type}[^",]{1,2000})""",
    """"identities"{1,20}:\["{1,20}({dest_host}[\w-]{1,2000})\.""",
    """"identities"{1,20}:\["{1,20}({user_fullname}.+?)\s{0,100}\(({user_email}({user}[^@]{1,2000})@[^\)"]{1,2000})"""
    """"categories"{1,20}:\["{1,20}({categories}[^"]{1,2000})"""", 
  ]


}
```