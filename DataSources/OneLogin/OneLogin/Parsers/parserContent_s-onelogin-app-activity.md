#### Parser Content
```Java
{
Name = s-onelogin-app-activity
  Vendor = OneLogin
  Product = OneLogin
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """assuming_acting_user_id":""", """app_name":""", """user_name":""", """event_type_id":""" ]
  Fields = [
    """"created_at":\s*"({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z)""",
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """"app_name":\s*"\s*({app}([^\\"]|(\\\\)*\\"|\\\\)+?)\s*"""",
    """"event_type_id":\s*({activity_code}\d+)""",
    """"user_name":\s*"({user_fullname}([^\\"]|(\\\\)*\\"|\\\\)+)"""",
    """"ipaddr":\s*"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """"notes":\s*"({failure_reason}([^\\"]|(\\\\)*\\"|\\\\)+)"""",
    """"notes":\s*"({additional_info}([^\\"]|(\\\\)*\\"|\\\\)+)"""",
    """"custom_message":\s*"({additional_info}([^\\"]|(\\\\)*\\"|\\\\)+)"""",
    """"error_description":\s*"({additional_info}([^\\"]|(\\\\)*\\"|\\\\)+)"""",
    
  ]
  DupFields = ["user_fullname->user"]
}
```