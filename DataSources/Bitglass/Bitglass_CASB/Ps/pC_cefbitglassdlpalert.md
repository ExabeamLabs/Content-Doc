#### Parser Content
```Java
{
Name = cef-bitglass-dlp-alert
  Vendor = Bitglass
  Product = Bitglass CASB
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """"action":"Alert"""", """"patterns":"""", """"application":"""", """"filelink":"""", """destinationServiceName =Bitglass""" ]
  Fields = [
    """"time":"({time}\d\d\s\w{1,3}\s\d\d\d\d\s\d\d:\d\d:\d\d)"""",
    """"patterns":"({alert_name}[^"]{1,2000})"""",
    """"status":"({alert_type}[^"]{1,2000})"""",
    """"folder":"({target}[^"]{1,2000})"""",
    """"filename":"({file_name}[^"]{1,2000}?(\.({file_ext}[^"]{1,2000}))?)"""",
    """"application":"({process}[^"]{1,2000})"""",
    """"owner":"({user_email}[^"]{1,2000})"""",
    """"filelink":"({additional_info}[^"]{1,2000})""""
  ]


}
```