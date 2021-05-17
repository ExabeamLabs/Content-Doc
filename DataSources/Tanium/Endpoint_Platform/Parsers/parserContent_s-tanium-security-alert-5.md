#### Parser Content
```Java
{
Name = s-tanium-security-alert-5
    Vendor = Tanium
    Product = Endpoint Platform
    Lms = Default
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """TaniumDetect""", """Timestamp""", """Computer Name""", """Computer IP""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """"Timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)"""",
      """"User Name":"({user}[^",]{1,2000}?)"""",
      """"User Id":"({user}[^",]{1,2000}?)"""",
      """"User Domain":"({domain}[^",]{1,2000}?)"""",
      """"user\\*":\\*"((NT-AUTORITÄT|NT AUTHORITY|({domain}[^"\\]{1,2000}))\\+)?(Système|SYSTEM|({user}[^"]{1,2000}?))\\*"""",
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
      """"Intel Name"{1,20}:"{1,20}({alert_name}[^"]{1,2000})""",
      """"Intel Type"{1,20}:"{1,20}({alert_type}[^"]{1,2000})""",
      """"Intel Labels":"({additional_info}[^"]{1,2000})"""
    ]
}
```