#### Parser Content
```Java
{
Name = q-box-app-activity
  Vendor = Box
  Product = Box Cloud Content Management
  Lms = QRadar
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """created_by"""", """created_at"""", """event_id"""", """event_type"""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """\d{1,100}:\d{1,100} ({host}[^\s]+) \{""",
    """[^\w]created_at"{1,20}\s{0,100}:\s{0,100}"{1,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d)[",\]\}]""",
    """[^\w]ip_address"{1,20}\s{0,100}:\s{0,100}"{1,20}(Unknown IP|({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))[",\]\}]""",
    """[^\w]created_by"{1,20}\s{0,100}:\s{0,100}[^\}]+?[^\w]name"{1,20}\s{0,100}:\s{0,100}"{1,20}({user_fullname}[^":,]+)[",\]\}]""",
    """[^\w]created_by"{1,20}\s{0,100}:\s{0,100}[^\}]+?[^\w]login"{1,20}\s{0,100}:\s{0,100}"{1,20}(|({user_email}.+?))[",\]\}]""",
    """[^\w]created_by"{1,20}\s{0,100}:\s{0,100}[^\}]+?[^\w]login"{1,20}\s{0,100}:\s{0,100}"{1,20}.*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))""",
    """[^\w]event_type"{1,20}\s{0,100}:\s{0,100}"{1,20}({accesses}[^",]+)[",\]\}]""",
    """({app}Box|Okta)""",
    """[^\w]additional_details"{1,20}\s{0,100}:\s{0,100}[^\}]+[^\w]size"{1,20}\s{0,100}:\s{0,100}({file_size}\d{1,100})[",\]\}]""",
    """[^\w]folder_name"{1,20}\s{0,100}:\s{0,100}"{1,20}({file_name}.+?)[",\]\}]""",
    """[^\w]item_name"{1,20}\s{0,100}:\s{0,100}"{1,20}({file_name}.+?)[",\]\}]""",
    """[^\w]item_name"{1,20}\s{0,100}:\s{0,100}"{1,20}[^,]+?\.({file_ext}[^,\."]+)[",\]\}]""",
    """[^\w]item_type"{1,20}\s{0,100}:\s{0,100}"{1,20}({file_type}[^",]+)[",\]\}]""",
    """[^\w]parent"{1,20}\s{0,100}:\s{0,100}[^\}]+?[^\w]name"{1,20}\s{0,100}:\s{0,100}"{1,20}({file_parent}[^",]+)[",\]\}]""",
    """[^\w]additional_details"{1,20}\s{0,100}:\s{0,100}\{({additional_info}[^\}]+)[",\]\}]""",
    """[^\w]accessible_by"{1,20}\s{0,100}:\s{0,100}[^\}]+?[^\w]name"{1,20}\s{0,100}:\s{0,100}"{1,20}[^":,]*[",\]\}],"login":"({target_user}[^":,]+?)"}""" ,
    """"role":"({access_type}[^"]+)"""",
     
  ]
  DupFields = [ "user_email->user", "accesses->activity", "host->dest_host" ]
}
```