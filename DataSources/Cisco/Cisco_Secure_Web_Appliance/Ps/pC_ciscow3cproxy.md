#### Parser Content
```Java
{
Name = cisco-w3c-proxy
    Vendor = Cisco
    Product = Cisco Secure Web Appliance
    Lms = Splunk
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch_sec"
    Conditions = [ """cisco:webbrowsing"""]
    Fields = [
		"""({time}\d{10})\.\d{3}""",
		"""exabeam_host=({host}[^\s]{1,2000})""",
                """\d{10}\.\d{3}\s{1,100}[^\s]{1,2000}\s(?:-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\s([^\s]{1,2000}\s){2}(?:-|"(({domain}[^\\]{1,2000})\\+)?({user}[^@"]{1,2000})[^"]{0,2000}")\s(?:-|({bytes_out}\d{1,100}))\s(?:-|({bytes_in}\d{1,100}))\s(?:-|({result_code}\d{1,100}))\s(?:-|({proxy_action}[^\s]{1,2000}))\s(?:-|({method}[^\s]{1,2000}))\s(?:-|(({protocol}[^:]{1,2000}):\/+)?({full_url}({web_domain}(?:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\s\/:]{1,2000}))(:({dest_port}\d{1,100}))?(?:-|({uri_path}\/[^?\s]{0,2000}))?({uri_query}\?[^\s]{1,2000})?))\s(("[^"]{1,2000}")|[^\s]{1,2000})\s{1,100}[^\s]{1,2000}\s(?:-|({dest_ip}[^\s]{1,2000}))\s([^\s]{1,2000}\s){2}(?:-|"({category}[^"]{1,2000})")\s[^\s]{1,2000}\s(?:-|({mime}[^\s]{1,2000}))\s(("[^"]{1,2000}")|[^\s]{1,2000})\s(?:-|"({user_agent}[^"]{1,2000})")\s(?:-|({action}[^-\s]{1,2000}))""",
    ]
  

}
```