#### Parser Content
```Java
{
Name = s-azure-app-activity
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"eventTimestamp":""", """"caller":""", """"resourceProviderName":""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"resourceProviderName":\s{0,100}\{[^\}]{0,2000}?"localizedValue":\s{0,100}"({resource}[^"]{1,2000})"""",
    """"eventTimestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """"operationName":\s{0,100}\{[^\}]{0,2000}?"localizedValue":\s{0,100}"({activity}[^"]{1,2000})"""",
    """"caller":\s{0,100}"({user}[^"\s@]{1,2000})"""",
    """"caller":\s{0,100}"({user_email}[^"\s@]{1,2000}@({email_domain}[^"\s@]{1,2000}))"""",
    """"httpRequest":\s{0,100}\{[^\}]{0,2000}?"clientIpAddress":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})""",
  ]
}
```