#### Parser Content
```Java
{
Name = cef-cisco-dns-response-1
  Vendor = Cisco
  Product = OpenDNS Umbrella
  Lms = ArcSight
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""CEF:0|Skyformation""", """requestClientApplication=Umbrella""", """cs6Label=raw-event"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """cs6="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)","[^"]*","({user_lastname}[^",]+),\s*({user_firstname}[^",\s]+)\s*\(({domain}[^\(\)]+)\)\s*\(({user}[^\(\)]+)\)[^"]*?","(|({dest_ip}[a-fA-F:\d.]+))",("[^"]+",)"(|({outcome}[^"]+))","[^"]+\(({query_type}[^\)]+)\)(",")(|({dns_response_code}[^"]+))(",")(|({query}[^"]+))(",")(|({category}[^"]+))"""",
  ]
}
```