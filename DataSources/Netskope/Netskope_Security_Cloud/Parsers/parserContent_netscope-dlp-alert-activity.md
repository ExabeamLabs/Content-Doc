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
      """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
      """"dstip"{1,20}:"{1,20}({dest_ip}[^"]+)"""",
      """"file_type"{1,20}:"{1,20}({file_type}[^"]+)"""",
      """"app"{1,20}:"{1,20}({app}[^"]+)"""",
      """"device"{1,20}:"{1,20}({device_type}[^"]+)"""",
      """"alert_type"{1,20}:"{1,20}({alert_type}[^"]+)"""",
      """"hostname"{1,20}:"{1,20}({host}[^"]+)"""",
      """"policy"{1,20}:"{1,20}({alert_name}[^"]+)"""",
      """"action"{1,20}:"{1,20}({action}[^"]+)"""",
      """"referer"{1,20}:"{1,20}({referrer}[^"]+)"""",
      """"user"{1,20}:"{1,20}({user}[^"]+)"""",
      """"srcip"{1,20}:"{1,20}({src_ip}[^"]+)"""",
      """"category"{1,20}:"{1,20}({category}[^"]+)""""
      """"{1,20}activity"{1,20}:"{1,20}({activity}[^"]+)"{1,20}""",
      """"object"{1,20}:"{1,20}({file_name}[^"]+)"""",
      """"{1,20}ccl"{1,20}:"{1,20}({alert_severity}[^"]+)"{1,20}""",
      """"{1,20}md5"{1,20}:"{1,20}({md5}[^"]+)"{1,20}""",
      """"{1,20}request_id"{1,20}:({alert_id}[^,]+)""",
      """proto=({protocol}[^"]+)\srequestClientApplication""",
      """outcome=({outcome}[^ ]+)""",
      """ext_url=({full_url}[^ ]+)""",
      """"from_user"{1,20}:"{1,20}({from_user_at}[^"]+)"""",
      """"shared_with"{1,20}:"{1,20}({shared_with_at}[^"]+)"""",
      """"sha256"{1,20}:"{1,20}({sha256_at}[^"]+)"""",
      """"site"{1,20}:"{1,20}({site_at}[^"]+)""""
    ]
}
```