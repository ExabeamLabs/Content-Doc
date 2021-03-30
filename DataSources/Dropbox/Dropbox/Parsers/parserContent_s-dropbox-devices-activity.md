#### Parser Content
```Java
{
Name = s-dropbox-devices-activity
    Vendor = Dropbox
    Product = Dropbox
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """"event_category": "devices"""", """"info_dict":""", """"event_type_description":""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"name":\s*"(?:N\/A|({user_fullname}[^"@,]+))"""",
      """"name":\s*"(?:N\/A|(({domain}[^"@\\\s]+)\\+)?({user}[^"@\\\s]+))"""",
      """"email":\s*"(?:N\/A|({user_email}[^@"\s]+@({email_domain}[^@"\s]+)))""",
      """"time":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\d:+-]+)"""",
      """"event_type":\s*"({activity}[^"]+)"""",
      """"event_type_description":\s*"({additional_info}[^"]+)"""",
      """"ip_address":\s*"({src_ip}[a-fA-F\d.:]+)""",
      """"display_name":\s*"({src_host}[\w\-.]+)\s*"""",
      """"platform":\s*"({os}[^"]+)"""",
      """"info_dict":\s*\{[^\}]*?"name":\s*"({app}[^"]+)""""
    ]
  }
```