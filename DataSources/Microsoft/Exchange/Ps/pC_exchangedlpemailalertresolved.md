#### Parser Content
```Java
{
Name = exchange-dlp-email-alert-resolved
  Conditions = [ ""","Resolved",""" ]

exchange-dlp-email-alert = {
  Vendor = Microsoft
  Product = Exchange
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy/MM/dd H:mm:ss"
  Fields = [
    """^.*?\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}"<""",
    """"({time}\d{1,100}/\d{1,100}/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100}) (am|AM|pm|PM)","(({sender}[^"@]{1,2000}@[^"@]{1,2000})|[^"]{0,2000})","(({recipients}({recipient}[^",;@]{1,2000}@[^",;@]{1,2000})[^"]{0,2000})|[^"]{0,2000})",(|""|"({src_ip}[a-fA-F\d.:]{1,2000})"),(|""|"({dest_ip}[a-fA-F\d.:]{1,2000})"),(|""|"({subject}.+?)\s{0,100}"),"({outcome}Delivered|Expanded|Failed|Resolved|FilteredAsSpam|Quarantined)",(|""|"({bytes}\d{1,100})")(,|\s{0,100}$)""",
    """"({host}[\w\-.]{1,2000})",([^,]{0,2000},){4}"{0,20}({time}\d\d\d\d\/\d\d\/\d\d\s{1,100}\d{1,2}:\d\d:\d\d)"{0,20},"{0,20}(<>|({sender}[^",;\s@]{1,2000}@[^",;\s@]{1,2000}))"{0,20},"{0,20}({recipients}({recipient}[^",;\s@]{1,2000}@[^",;\s@]{1,2000})[^"]{0,2000})"{0,20},"{0,20}(|({subject}.+?))\s{0,100}"{0,20},"{0,20}({outcome}Delivered|Expanded|Failed)"{0,20},"{0,20}(|({dest_ip}[A-Fa-f:\d.]{1,2000}))"{0,20},"{0,20}(|({src_ip}[A-Fa-f:\d.]{1,2000}))"{0,20},"{0,20}({bytes}\d{1,100})""",
  
}
```