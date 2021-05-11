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
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"name":\s{0,100}"(?:N\/A|({user_fullname}[^"@,]+))"""",
      """"name":\s{0,100}"(?:N\/A|(({domain}[^"@\\\s]+)\\+)?({user}[^"@\\\s]+))"""",
      """"email":\s{0,100}"(?:N\/A|({user_email}[^@"\s]+@({email_domain}[^@"\s]+)))""",
      """"time":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\d:+-]+)"""",
      """"event_type":\s{0,100}"({activity}[^"]+)"""",
      """"event_type_description":\s{0,100}"({additional_info}[^"]+)"""",
      """"ip_address":\s{0,100}"({src_ip}[a-fA-F\d.:]+)""",
      """"display_name":\s{0,100}"({src_host}[\w\-.]+)\s{0,100}"""",
      """"platform":\s{0,100}"({os}[^"]+)"""",
      """"info_dict":\s{0,100}\{[^\}]*?"name":\s{0,100}"({app}[^"]+)""""
    ]
  }
```