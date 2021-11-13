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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"name":\s{0,100}"(?:N\/A|({user_fullname}[^"@,]{1,2000}))"""",
      """"name":\s{0,100}"(?:N\/A|(({domain}[^"@\\\s]{1,2000})\\+)?({user}[^"@\\\s]{1,2000}))"""",
      """"email":\s{0,100}"(?:N\/A|({user_email}[^@"\s]{1,2000}@({email_domain}[^@"\s]{1,2000})))""",
      """"time":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\d:+-]{1,2000})"""",
      """"event_type":\s{0,100}"({activity}[^"]{1,2000})"""",
      """"event_type_description":\s{0,100}"({additional_info}[^"]{1,2000})"""",
      """"ip_address":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})""",
      """"doc_title":\s{0,100}"({object}[^"]{1,2000})"""",
      """"recipient_email":\s{0,100}"({resource}[^"]{1,2000})""""
    ]
  

}
```