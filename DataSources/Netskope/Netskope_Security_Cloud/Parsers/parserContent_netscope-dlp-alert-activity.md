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
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d+Z),""",
      """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
      """"dstip"+:"+({dest_ip}[^"]+)"""",
      """"file_type"+:"+({file_type}[^"]+)"""",
      """"app"+:"+({app}[^"]+)"""",
      """"device"+:"+({device_type}[^"]+)"""",
      """"alert_type"+:"+({alert_type}[^"]+)"""",
      """"hostname"+:"+({host}[^"]+)"""",
      """"policy"+:"+({alert_name}[^"]+)"""",
      """"action"+:"+({action}[^"]+)"""",
      """"referer"+:"+({referrer}[^"]+)"""",
      """"user"+:"+({user}[^"]+)"""",
      """"srcip"+:"+({src_ip}[^"]+)"""",
      """"category"+:"+({category}[^"]+)""""
      """"+activity"+:"+({activity}[^"]+)"+""",
      """"object"+:"+({file_name}[^"]+)"""",
      """"+ccl"+:"+({alert_severity}[^"]+)"+""",
      """"+md5"+:"+({md5}[^"]+)"+""",
      """"+request_id"+:({alert_id}[^,]+)""",
      """proto=({protocol}[^"]+)\srequestClientApplication""",
      """outcome=({outcome}[^ ]+)""",
      """ext_url=({full_url}[^ ]+)""",
      """"from_user"+:"+({from_user_at}[^"]+)"""",
      """"shared_with"+:"+({shared_with_at}[^"]+)"""",
      """"sha256"+:"+({sha256_at}[^"]+)"""",
      """"site"+:"+({site_at}[^"]+)""""
    ]
}
```