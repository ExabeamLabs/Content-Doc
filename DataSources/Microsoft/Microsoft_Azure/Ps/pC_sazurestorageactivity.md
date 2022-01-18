#### Parser Content
```Java
{
Name = s-azure-storage-activity
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "cloud-storage-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """resourceProviderName":{"value":"Microsoft.Storage"""  ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"resourceProviderName":\s{0,100}\{[^\}]{0,2000}?"localizedValue":\s{0,100}"({service}[^"]{1,2000})"""",
    """"eventTimestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"operationName":\s{0,100}\{[^\}]{0,2000}?"localizedValue":\s{0,100}"({activity}[^"]{1,2000})"""",
    """"caller":\s{0,100}"({user}[^"\s@]{1,2000})"""",
    """"caller":\s{0,100}"({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})"""",
    """"httpRequest":\s{0,100}\{[^\}]{0,2000}?"clientIpAddress":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"tenantId":"({account_id}[^"]{1,2000})""",
    """"status":\{"value":"({outcome}[^"]{1,2000})""",
    """"resourceId".+?\/containers\/({bucket}[^\/"])""",
  ]
   DupFields = ["event_hub_namespace->host"]


}
```