#### Parser Content
```Java
{
Name = netscaler-web-activity-1
  Vendor = Citrix Netscaler
  Product = Web Logging
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy:HH:mm:ss z"
  Conditions = [ """ SSLVPN HTTPREQUEST """, """ User """, """ : SSO is """ ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """((\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+)?<\d+>)?\s+({time}\d+\/\d+\/\d+:\d+:\d+:\d+\s+\w+)\s+({dest_host}[\w\-.]+).+?({user}[^\s@]+)@({src_ip}[A-Fa-f:\d.]+).+?({web_domain}[^\s]+)\s+User\s+({=user}[^\s:]+).+?Vserver\s+({dest_ip}[A-Fa-f:\d.]+?):({dest_port}\d+).+?SSO is (ON|OFF)\s*:\s*({method}\S+)\s+({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?\s+""",
    """({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|media|goog|ae|corp))+)\s+User"""
  ]
}
```