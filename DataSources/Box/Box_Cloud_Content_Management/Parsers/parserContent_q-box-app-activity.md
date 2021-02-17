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
    """\d+:\d+ ({host}[^\s]+) \{""",
    """[^\w]created_at"+\s*:\s*"+({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d)[",\]\}]""",
    """[^\w]ip_address"+\s*:\s*"+(Unknown IP|({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))[",\]\}]""",
    """[^\w]created_by"+\s*:\s*[^\}]+?[^\w]name"+\s*:\s*"+({user_fullname}[^":,]+)[",\]\}]""",
    """[^\w]created_by"+\s*:\s*[^\}]+?[^\w]login"+\s*:\s*"+(|({user_email}.+?))[",\]\}]""",
    """[^\w]created_by"+\s*:\s*[^\}]+?[^\w]login"+\s*:\s*"+.*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))""",
    """[^\w]event_type"+\s*:\s*"+({accesses}[^",]+)[",\]\}]""",
    """({app}Box|Okta)""",
    """[^\w]additional_details"+\s*:\s*[^\}]+[^\w]size"+\s*:\s*({file_size}\d+)[",\]\}]""",
    """[^\w]folder_name"+\s*:\s*"+({file_name}.+?)[",\]\}]""",
    """[^\w]item_name"+\s*:\s*"+({file_name}.+?)[",\]\}]""",
    """[^\w]item_name"+\s*:\s*"+[^,]+?\.({file_ext}[^,\."]+)[",\]\}]""",
    """[^\w]item_type"+\s*:\s*"+({file_type}[^",]+)[",\]\}]""",
    """[^\w]parent"+\s*:\s*[^\}]+?[^\w]name"+\s*:\s*"+({file_parent}[^",]+)[",\]\}]""",
    """[^\w]additional_details"+\s*:\s*\{({additional_info}[^\}]+)[",\]\}]""",
    """[^\w]accessible_by"+\s*:\s*[^\}]+?[^\w]name"+\s*:\s*"+[^":,]*[",\]\}],"login":"({target_user}[^":,]+?)"}""" ,
    """"role":"({access_type}[^"]+)"""",
     
  ]
  DupFields = [ "user_email->user", "accesses->activity", "host->dest_host" ]
}
```