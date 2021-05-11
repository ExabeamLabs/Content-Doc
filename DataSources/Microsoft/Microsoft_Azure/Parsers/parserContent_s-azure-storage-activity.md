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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """"resourceProviderName":\s{0,100}\{[^\}]*?"localizedValue":\s{0,100}"({service}[^"]+)"""",
    """"eventTimestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"operationName":\s{0,100}\{[^\}]*?"localizedValue":\s{0,100}"({activity}[^"]+)"""",
    """"caller":\s{0,100}"({user}[^"\s@]+)"""",
    """"caller":\s{0,100}"({user_email}[^"\s@]+@[^"\s@]+)"""",
    """"httpRequest":\s{0,100}\{[^\}]*?"clientIpAddress":\s{0,100}"({src_ip}[a-fA-F\d.:]+)""",
    """"tenantId":"({account_id}[^"]+)""",
    """"status":\{"value":"({outcome}[^"]+)""",
    """"resourceId".+?\/containers\/({bucket}[^\/"])""",
  ]
   DupFields = ["event_hub_namespace->host"]
}
```