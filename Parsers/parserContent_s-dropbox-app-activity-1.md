#### Parser Content
```Java
{
Name = s-dropbox-app-activity-1
    Vendor = Dropbox
    Product = Dropbox
    Lms = Splunk
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """"event_category": "sharing"""", """"info_dict":""", """"event_type": "sf_request_access"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"name":\s*"(?:N\/A|({user_fullname}[^"@,]+))"""",
      """"name":\s*"(?:N\/A|(({domain}[^"@\\\s]+)\\+)?({user}[^"@\\\s]+))"""",
      """"email":\s*"(?:N\/A|({user_email}[^@"\s]+@[^@"\s]+))""",
      """"time":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\d:+-]+)"""",
      """"event_type":\s*"({activity}[^"]+)"""",
      """"event_type_description":\s*"({additional_info}[^"]+)"""",
      """"ip_address":\s*"({src_ip}[a-fA-F\d.:]+)""",
      """"folder_name":\s*"({object}[^"]+)""""
    ]
  }
```