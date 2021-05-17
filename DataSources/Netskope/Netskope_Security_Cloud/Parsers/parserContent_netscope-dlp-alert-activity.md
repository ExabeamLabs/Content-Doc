#### Parser Content
```Java
{
Name = netscope-dlp-alert-activity
  Vendor = Netskope
  Product = Netskope Security Cloud 
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """SkyFormation Cloud Apps Security""","""destinationServiceName=Netskope""","""alert_type""","""DLP"""]
  Fields =[  
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,100}Z),""",
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """"dstip"{1,20}:"{1,20}({dest_ip}[^"]{1,2000})"""",
      """"file_type"{1,20}:"{1,20}({file_type}[^"]{1,2000})"""",
      """"app"{1,20}:"{1,20}({app}[^"]{1,2000})"""",
      """"device"{1,20}:"{1,20}({device_type}[^"]{1,2000})"""",
      """"alert_type"{1,20}:"{1,20}({alert_type}[^"]{1,2000})"""",
      """"hostname"{1,20}:"{1,20}({host}[^"]{1,2000})"""",
      """"policy"{1,20}:"{1,20}({alert_name}[^"]{1,2000})"""",
      """"action"{1,20}:"{1,20}({action}[^"]{1,2000})"""",
      """"referer"{1,20}:"{1,20}({referrer}[^"]{1,2000})"""",
      """"user"{1,20}:"{1,20}({user}[^"]{1,2000})"""",
      """"srcip"{1,20}:"{1,20}({src_ip}[^"]{1,2000})"""",
      """"category"{1,20}:"{1,20}({category}[^"]{1,2000})""""
      """"{1,20}activity"{1,20}:"{1,20}({activity}[^"]{1,2000})"{1,20}""",
      """"object"{1,20}:"{1,20}({file_name}[^"]{1,2000})"""",
      """"{1,20}ccl"{1,20}:"{1,20}({alert_severity}[^"]{1,2000})"{1,20}""",
      """"{1,20}md5"{1,20}:"{1,20}({md5}[^"]{1,2000})"{1,20}""",
      """"{1,20}request_id"{1,20}:({alert_id}[^,]{1,2000})""",
      """proto=({protocol}[^"]{1,2000})\srequestClientApplication""",
      """outcome=({outcome}[^ ]{1,2000})""",
      """ext_url=({full_url}[^ ]{1,2000})""",
      """"from_user"{1,20}:"{1,20}({from_user_at}[^"]{1,2000})"""",
      """"shared_with"{1,20}:"{1,20}({shared_with_at}[^"]{1,2000})"""",
      """"sha256"{1,20}:"{1,20}({sha256_at}[^"]{1,2000})"""",
      """"site"{1,20}:"{1,20}({site_at}[^"]{1,2000})""""
    ]
}
```