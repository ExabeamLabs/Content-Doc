#### Parser Content
```Java
{
Name = s-dropbox-app-activity-2
    Vendor = Dropbox
    Product = Dropbox
    Lms = Splunk
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """"event_category": "sharing"""", """"info_dict":""", """"event_type": "paper_doc_team_mention"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"name":\s{0,100}"(?:N\/A|({user_fullname}[^"@,]+))"""",
      """"name":\s{0,100}"(?:N\/A|(({domain}[^"@\\\s]+)\\+)?({user}[^"@\\\s]+))"""",
      """"email":\s{0,100}"(?:N\/A|({user_email}[^@"\s]+@({email_domain}[^@"\s]+)))""",
      """"time":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\d:+-]+)"""",
      """"event_type":\s{0,100}"({activity}[^"]+)"""",
      """"event_type_description":\s{0,100}"({additional_info}[^"]+)"""",
      """"ip_address":\s{0,100}"({src_ip}[a-fA-F\d.:]+)""",
      """"doc_title":\s{0,100}"({object}[^"]+)"""",
      """"recipient_email":\s{0,100}"({resource}[^"]+)""""
    ]
  }
```