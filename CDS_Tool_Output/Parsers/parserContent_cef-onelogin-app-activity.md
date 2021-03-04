#### Parser Content
```Java
{
Name = cef-onelogin-app-activity
  Vendor = OneLogin
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """assuming_acting_user_id":""", """app_name":""", """user_name":""", """event_type_id":""" ]
  Fields = [
    """"created_at":\s*"({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)""",
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """\WdestinationServiceName=({app}\w+)""",
    """"app_name":\s*"\s*({app}([^\\"]|(\\\\)*\\"|\\\\)+?)\s*"""",
    """"event_type_id":\s*({activity_code}\d+)""",
    """"user_name":\s*"\s*({user_fullname}([^\\"]|(\\\\)*\\"|\\\\)+?)\s*"""",
    """"ipaddr":\s*"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """"notes":\s*"\s*({failure_reason}([^\\"]|(\\\\)*\\"|\\\\)+?)\s*"""",
    """"notes":\s*"\s*({additional_info}([^\\"]|(\\\\)*\\"|\\\\)+?)\s*"""",
    """"custom_message":\s*"\s*({additional_info}([^\\"]|(\\\\)*\\"|\\\\)+?)\s*"""",
    """"error_description":\s*"\s*({additional_info}([^\\"]|(\\\\)*\\"|\\\\)+?)\s*"""",
    """\Wmsg=\s*({additional_info}.+?)(\s+\w+=|\s*$)""",
  ]
}
```