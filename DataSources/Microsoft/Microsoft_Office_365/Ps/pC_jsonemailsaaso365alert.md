#### Parser Content
```Java
{
Name = json-email-saas-o365-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSS"
  Conditions = [ """office365""", """"d:FromIP"""", """"d:Organization"""", """"d:Subject"""", "MessageTrace" ]
  Fields = [
    """"d:Received":.+?#text":\s{0,100}"({time}[^"]{1,2000})"""", 
    """"d:SenderAddress":\s{0,100}"({sender}[^"]{1,2000})"""",
    """"d:RecipientAddress":\s{0,100}"({recipient}[^"]{1,2000})"""",
    """"d:Subject"":\s{0,100}"({subject}[^"]{1,2000})"""",
    """"d:Organization":\s{0,100}""({domain}[^"]{1,2000})"""",
    """"d:StartDate":.+?#text"":\s{0,100}"({time_started}[^"]{1,2000})"""",
    """"d:EndDate":.+?#text"":\s{0,100}"({time_ended}[^"]{1,2000})"""",
    """"d:FromIP":\s{0,100}"({src_ip}[^"]{1,2000})"""",
    """"d:Size":.+?#text":\s{0,100}""({bytes}[^"]{1,2000})"""",
    """"d:Status":\s{0,100}"({outcome}[^"]{1,2000})"""",
  ]
  DupFields = [ "subject->alert_name" ]


}
```