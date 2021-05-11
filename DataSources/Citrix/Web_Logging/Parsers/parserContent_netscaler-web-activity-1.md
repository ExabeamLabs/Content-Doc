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
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """((\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]+)\s{1,100})?<\d{1,100}>)?\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}:\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\w+)\s{1,100}({dest_host}[\w\-.]+).+?({user}[^\s@]+)@({src_ip}[A-Fa-f:\d.]+).+?({web_domain}[^\s]+)\s{1,100}User\s{1,100}({=user}[^\s:]+).+?Vserver\s{1,100}({dest_ip}[A-Fa-f:\d.]+?):({dest_port}\d{1,100}).+?SSO is (ON|OFF)\s{0,100}:\s{0,100}({method}\S+)\s{1,100}({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?\s{1,100}""",
    """({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|media|goog|ae|corp))+)\s{1,100}User"""
  ]
}
```