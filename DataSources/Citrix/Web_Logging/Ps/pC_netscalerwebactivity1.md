#### Parser Content
```Java
{
Name = netscaler-web-activity-1
  Vendor = Citrix
  Product = Web Logging
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy:HH:mm:ss z"
  Conditions = [ """ SSLVPN HTTPREQUEST """, """ User """, """ : SSO is """ ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """((\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100})?<\d{1,100}>)?\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}:\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\w+)\s{1,100}({dest_host}[\w\-.]{1,2000}).+?({user}[^\s@]{1,2000})@({src_ip}[A-Fa-f:\d.]{1,2000}).+?({web_domain}[^\s]{1,2000})\s{1,100}User\s{1,100}({=user}[^\s:]{1,2000}).+?Vserver\s{1,100}({dest_ip}[A-Fa-f:\d.]{1,2000}?):({dest_port}\d{1,100}).+?SSO is (ON|OFF)\s{0,100}:\s{0,100}({method}\S+)\s{1,100}({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?\s{1,100}""",
    """({top_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|media|goog|ae|corp))+)\s{1,100}User"""
  ]


}
```