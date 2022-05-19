#### Parser Content
```Java
{
Name = cef-netskope-web-activity-1
  Conditions = [ """"page":"""", """"traffic_type":"CloudApp"""", """"url":"""" ]

cef-netskope-web = {
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  TimeFormat = "epoch_sec"
  DataType = "web-activity"
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"timestamp":({time}\d{1,100})""",
    """"hostname":"({src_host}[^"]{1,2000})""",
    """"userip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"appcategory":"({category}[^"]{1,2000})""",
    """"other_categories":\[({categories}[^\]]{1,2000}?)\]"""
    """"action":"({action}[^"]{1,2000})""",
    """"page":"({full_url}(\w+:\/\/)?(({dest_ip}[A-Fa-f.:\d]{1,2000})|({web_domain}[^\/]{1,2000}?))({uri_path}\/[^\?]{0,2000}?)?({uri_query}\?[^"]{1,2000})?)"""",
    """"policy":"({additional_info}[^"]{1,2000})""",
    """"page":"(\w+:\/\/)?({web_domain}[^\\\/"]{1,2000})""",
    """"user":"\s{0,100}({user_email}[^\s"@]{1,2000}?@[^\s"]{1,2000}\.[^\s"]{1,2000})"""",
    """"dstip":"({dest_ip}[A-Fa-f.:\d]{1,2000})""",
    """"browser":"(unknown|({browser}[^"]{1,2000}))""",
    """"src_location":"({src_location}[^"]{1,2000})""",
    """"src_country":"({src_country}[^"]{1,2000})""",
    """"os":"({os}[^"]{1,2000})""",
    """"referer":"({referrer}[^"]{1,2000})"""
  
}
```