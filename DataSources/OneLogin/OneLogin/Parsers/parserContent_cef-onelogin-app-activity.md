#### Parser Content
```Java
{
Name = cef-onelogin-app-activity
  Vendor = OneLogin
  Product = OneLogin
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """assuming_acting_user_id":""", """app_name":""", """user_name":""", """event_type_id":""" ]
  Fields = [
    """"created_at":\s{0,100}"({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)""",
    """CEF:([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """\WdestinationServiceName=({app}\w+)""",
    """"app_name":\s{0,100}"\s{0,100}({app}([^\\"]|(\\\\)*\\"|\\\\)+?)\s{0,100}"""",
    """"event_type_id":\s{0,100}({activity_code}\d{1,100})""",
    """"user_name":\s{0,100}"\s{0,100}({user_fullname}([^\\"]|(\\\\)*\\"|\\\\)+?)\s{0,100}"""",
    """"ipaddr":\s{0,100}"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"notes":\s{0,100}"\s{0,100}({failure_reason}([^\\"]|(\\\\)*\\"|\\\\)+?)\s{0,100}"""",
    """"notes":\s{0,100}"\s{0,100}({additional_info}([^\\"]|(\\\\)*\\"|\\\\)+?)\s{0,100}"""",
    """"custom_message":\s{0,100}"\s{0,100}({additional_info}([^\\"]|(\\\\)*\\"|\\\\)+?)\s{0,100}"""",
    """"error_description":\s{0,100}"\s{0,100}({additional_info}([^\\"]|(\\\\)*\\"|\\\\)+?)\s{0,100}"""",
    """\Wmsg=\s{0,100}({additional_info}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```