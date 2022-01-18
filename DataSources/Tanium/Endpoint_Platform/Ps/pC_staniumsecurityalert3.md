#### Parser Content
```Java
{
Name = s-tanium-security-alert-3
    Vendor = Tanium
    Product = Endpoint Platform
    Lms = Default
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """tanium-index""", """Timestamp""", """Computer Name""", """Computer IP""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """"Timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)"""",
      """"User Name":"({user}[^",]{1,2000}?)"""",
      """"User Id":"({user}[^",]{1,2000}?)"""",
      """"User Domain":"({domain}[^",]{1,2000}?)"""",
      """"user\\*":\\*"((NT AUTHORITY|({domain}[^"\\]{1,2000}))\\+)?(SYSTEM|({user}[^"]{1,2000}?))\\*"""",
      """"Priority":"({alert_severity}[^",]{1,2000})"""",
      """"Event Name":"({alert_name}[^",]{1,2000})"""",
      """"Event Name":"({alert_type}[^",]{1,2000})"""",
      """"type\\*":\\*"({alert_type}[^"]{1,2000}?)\\*"""",
      """"Event Id":"({alert_id}[^",]{1,2000})"""",
      """"Computer Name":"({src_host}[^"]{1,2000}?)"""",
      """"Computer IP":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
      """"fullpath\\*":\\*"({malware_url}[^"]{1,2000}?)\\*"""",
      """"name\\*":\\*"({file_name}[^"]{1,2000}?)\\*"""",
      """"source\\*":\\*"({log_source}[^"]{1,2000}?)\\*"""",
    ]
  

}
```