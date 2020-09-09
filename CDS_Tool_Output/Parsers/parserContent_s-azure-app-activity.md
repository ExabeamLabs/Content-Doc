#### Parser Content
```Java
{
Name = s-azure-app-activity
  Vendor = Microsoft 
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"eventTimestamp":""", """"caller":""", """"resourceProviderName":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"resourceProviderName":\s*\{[^\}]*?"localizedValue":\s*"({resource}[^"]+)"""",
    """"eventTimestamp":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"operationName":\s*\{[^\}]*?"localizedValue":\s*"({activity}[^"]+)"""",
    """"caller":\s*"({user}[^"\s@]+)"""",
    """"caller":\s*"({user_email}[^"\s@]+@[^"\s@]+)"""",
    """"httpRequest":\s*\{[^\}]*?"clientIpAddress":\s*"({src_ip}[a-fA-F\d.:]+)""",
  ]
}
```