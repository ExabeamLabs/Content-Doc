#### Parser Content
```Java
{
Name = s-opendns-dns-response-7
  Conditions = [ ""","Allowed","2 (NS)",""" ]

s-opendns-dns-response = {
  Vendor = Cisco
  Product = Cisco Umbrella
  Lms = Splunk
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)(",")(({user_fullname}[^"\(\)]{1,2000}[\s,]{1,100}[^"\(\)]{1,2000}?)|({user}[^\s"\(\)]{1,2000}))\s{0,100}((\()[^"]{0,2000}"|"),("[^"]{0,2000}",)"(|({dest_ip}[a-fA-F:\d.]{1,2000}))",("[^"]{0,2000}",)"(|({outcome}[^",]{1,2000}))"""",
    """Other(",")(|({dns_response_code}[^"]{1,2000}))(",")(|({query}[^"]{0,2000}?)\.?)(",")(|({categories}({category}[^",]{1,2000})[^"]{0,2000}))"""",
    """(\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)",("[^"]{0,2000}",){5}"[^"]{0,2000}\(({query_type}[^\)]{1,2000})\)(",")(|({dns_response_code}[^"]{1,2000}))(",")(|({query}[^"]{0,2000}?)\.?)(",")(|({categories}({category}[^",]{1,2000})[^"]{0,2000}))"""",
    """:\d\d:\d\d","[^"\(]{1,2000}?\(({user_email}[^\s"@]{1,2000}@({email_domain}[^\s"@\)\.]{1,2000}\.[^\s"@\)]{1,2000}))\)?","""
  
}
```