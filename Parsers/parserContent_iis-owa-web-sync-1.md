#### Parser Content
```Java
{
Name = iis-owa-web-sync-1
    Vendor = Microsoft
    Product = Microsoft Owa 
    Lms = Direct
    DataType = "web-activity"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """<custom conditions>"""]
    Fields = [
      """({time}\d+-\d+-\d+\s\d+:\d+:\d+)\s*({src_host}[^\s]+)?\s+\s*({method}[^\s]+)\s*({uri_path}[^\s]+)\s*[^\s]+\s+({dest_port}\d+)\s*-\s*({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s*({user_agent}[^\s]+)\s*(-|(https:\/\/|:http\/\/)({web_domain}.+?\.({top_domain}\w+\.\w+)))(\/|\/[^\s]+)?\s*({result_code}\d+)\s*\d+\s*\d+\s*\d*\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s*"""
    ]
}
```