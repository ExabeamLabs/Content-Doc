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
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"name":\s*"(?:N\/A|({user_fullname}[^"@,]+))"""",
      """"name":\s*"(?:N\/A|(({domain}[^"@\\\s]+)\\+)?({user}[^"@\\\s]+))"""",
      """"email":\s*"(?:N\/A|({user_email}[^@"\s]+@({email_domain}[^@"\s]+)))""",
      """"time":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\d:+-]+)"""",
      """"event_type":\s*"({activity}[^"]+)"""",
      """"event_type_description":\s*"({additional_info}[^"]+)"""",
      """"ip_address":\s*"({src_ip}[a-fA-F\d.:]+)""",
      """"doc_title":\s*"({object}[^"]+)"""",
      """"recipient_email":\s*"({resource}[^"]+)""""
    ]
  }

  {
    Name = s-dropbox-sharing-activity
    Vendor = Dropbox
    Product = Dropbox
    Lms = Splunk
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """"event_category": "sharing"""", """"info_dict":""", """"event_type_description":""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"name":\s*"(?:N\/A|({user_fullname}[^"@,]+))"""",
      """"name":\s*"(?:N\/A|(({domain}[^"@\\\s]+)\\+)?({user}[^"@\\\s]+))"""",
      """"email":\s*"(?:N\/A|({user_email}[^@"\s]+@[^@"\s]+))""",
      """"time":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\d:+-]+)"""",
      """"event_type":\s*"({event_subtype}[^"]+)"""",
      """"event_type_description":\s*"({accesses}[^"]+)"""",
      """"is_dir":\s*false,.*?({file_type}file)""",
      """"is_dir":\s*true,.*?({file_type}folder)""",
      """"({file_type}folder)_name":""",
      """"event_type_description":\s*"[^"]*?({file_type}link)""",
      """"ip_address":\s*"({src_ip}[a-fA-F\d.:]+)""",
      """"path":\s*"({file_path}({file_parent}[^"]+?\/)?({file_name}[^"/]+?({file_ext}\.[^"\\\/\s\d\.]+)?))"""",
      """"content_name":\s*"({file_name}[^"]+?({file_ext}\.[^"\\\/\s\d\.]+)?)"""",
      """"content_link":\s*"({directory_uri}[^"]+)"""",
      """"folder_name":\s*"({file_name}[^"]+?({file_ext}\.[^"\\\/\s\d\.]+)?)"""",
      """"base_name":\s*"({file_name}[^"]+?({file_ext}\.[^"\\\/\s\d\.]+)?)"""",
      """"orig_folder_name":\s*"({src_file_name}[^"]+)"""",
      """"doc_title":\s*"({file_name}[^"]+?({file_ext}\.[^"\\\/\s\d\.]+)?)"""",
      """"file_name":\s*"({file_name}[^"]+?({file_ext}\.[^"\\\/\s\d\.]+)?)"""",
      """"target_users":\s*\[[^\]]*?"email":\s*"({object}[^"]+)"""",
      """"recipient_email":\s*"({resource}[^"]+)""""
    ]
    DupFields = [ "host->dest_host" ]
  }

  {
    Name = s-dropbox-files-activity
    Vendor = Dropbox
    Product = Dropbox
    Lms = Splunk
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """"event_category": "files"""", """"info_dict":""", """"event_type_description":""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"name":\s*"(?:N\/A|({user_fullname}[^"@,]+))"""",
      """"name":\s*"(?:N\/A|(({domain}[^"@\\\s]+)\\+)?({user}[^"@\\\s]+))"""",
      """"email":\s*"(?:N\/A|({user_email}[^@"\s]+@[^@"\s]+))""",
      """"time":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\d:+-]+)"""",
      """"event_type":\s*"({event_subtype}[^"]+)"""",
      """"event_type_description":\s*"({accesses}[^"]+)"""",
      """"is_dir":\s*false,.*?({file_type}file)""",
      """"is_dir":\s*true,.*?({file_type}folder)""",
      """"({file_type}folder)_name":""",
      """"event_type_description":\s*"[^"]*?({file_type}link)""",
      """"ip_address":\s*"({src_ip}[a-fA-F\d.:]+)""",
      """"path":\s*"({file_path}({file_parent}[^"]+?\/?)?({file_name}[^"/]+?({file_ext}\.[^"\\\/\s\d\.]+)?))"""",
      """"folder_name":\s*"({file_name}[^"]+?({file_ext}\.[^"\\\/\s\d\.]+)?)"""",
      """"orig_folder_name":\s*"({src_file_name}[^"]+)"""",
      """"doc_title":\s*"({file_name}[^"]+?({file_ext}\.[^"\\\/\s\d\.]+)?)"""",
      """"doc_title":\s*"({object}[^"]+)"""",
      """"file_name":\s*"({file_name}[^"]+?({file_ext}\.[^"\\\/\s\d\.]+)?)""""
    ]
    DupFields = [ "host->dest_host" ]
  }

  {
    Name = s-dropbox-apps-activity
    Vendor = Dropbox
    Product = Dropbox
    Lms = Splunk
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """"event_category": "apps"""", """"info_dict":""", """"event_type_description":""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"name":\s*"(?:N\/A|({user_fullname}[^"@,]+))"""",
      """"name":\s*"(?:N\/A|(({domain}[^"@\\\s]+)\\+)?({user}[^"@\\\s]+))"""",
      """"email":\s*"(?:N\/A|({user_email}[^@"\s]+@({email_domain}[^@"\s]+)))""",
      """"time":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\d:+-]+)"""",
      """"event_type":\s*"({activity}[^"]+)"""",
      """"event_type_description":\s*"({additional_info}[^"]+)"""",
      """"ip_address":\s*"({src_ip}[a-fA-F\d.:]+)""",
      """"info_dict":\s*\{[^\}]*?"name":\s*"({app}[^"]+)""""
    ]
  }

  {
    Name = s-dropbox-logins-activity
    Vendor = Dropbox
    Product = Dropbox
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """"event_category": "logins"""", """"info_dict":""", """"event_type_description":""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"name":\s*"(?:N\/A|({user_fullname}[^"@,]+))"""",
      """"name":\s*"(?:N\/A|(({domain}[^"@\\\s]+)\\+)?({user}[^"@\\\s]+))"""",
      """"email":\s*"(?:N\/A|({user_email}[^@"\s]+@[^@"\s]+))""",
      """"time":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\d:+-]+)"""",
      """"event_type":\s*"({activity}[^"]+)"""",
      """"event_type_description":\s*"({additional_info}[^"]+)"""",
      """"ip_address":\s*"({src_ip}[a-fA-F\d.:]+)""",
      """"display_name":\s*"({user_agent}[^"]+)"""",
      """"display_name":\s*"Mozilla[^"]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    ]
  }

  {
    Name = s-dropbox-members-activity
    Vendor = Dropbox
    Product = Dropbox
    Lms = Splunk
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """"event_category": "members"""", """"info_dict":""", """"event_type_description":""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"name":\s*"(?:N\/A|({user_fullname}[^"@,]+))"""",
      """"name":\s*"(?:N\/A|(({domain}[^"@\\\s]+)\\+)?({user}[^"@\\\s]+))"""",
      """"email":\s*"(?:N\/A|({user_email}[^@"\s]+@({email_domain}[^@"\s]+)))""",
      """"time":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\d:+-]+)"""",
      """"event_type":\s*"({activity}[^"]+)"""",
      """"event_type_description":\s*"({additional_info}[^"]+)"""",
      """"ip_address":\s*"({src_ip}[a-fA-F\d.:]+)""",
      """"target_users":\s*\[[^\]]*?"email":\s*"({object}[^"]+)""""
    ]
  }

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

${DropboxParserTemplates.cef-dropbox-activity}{
  Name = cef-dropbox-app-activity-1
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"file_operations"}""" ]
}
```