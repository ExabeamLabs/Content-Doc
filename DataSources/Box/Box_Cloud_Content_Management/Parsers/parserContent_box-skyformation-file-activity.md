#### Parser Content
```Java
{
Name = box-skyformation-file-activity
  Vendor = Box
  Product = Box Cloud Content Management
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|Skyformation|""", """destinationServiceName=Box""", """"item_type":"""", """"item_name":"""" ]
  Fields = [
    """"{1,20}created_at"{1,20}:"{1,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d([\+\-]\d\d:\d\d)?)""",
    """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """created_by":[^\}]+?"login":"(anonymous|Unknown User|({user}[^\s@"]+))""",
    """created_by":[^\}]+?"login":"({user_email}[^\s@"]+@[^\s@"]+)""",
    """\ssuser=(anonymous|({user}[^\s@"]+))\s{1,100}(\w+=|$)""",
    """\ssuser=({user_email}[^\s@]+@[^\s@]+)\s{1,100}(\w+=|$)""",
    """"item_name":"({file_name}[^\.]+?)",""""
    """"item_name":"([^\.]+?|(({file_name}[^"]+?\.(|({file_ext}[^\."]+?)))))",""""    
    """"item_type":"({file_type}[^"]+)""",
    """\sfname=({file_name}.+?)\s{1,100}(\w+=|$)""",
    """"parent":\{[^\}]*?"name":"({file_parent}[^"]+)""",
    """"event_type":"({accesses}[^"]+)""",
    """additional_details":\{[^\}]*?"size":({bytes}\d{1,100})""",
    """(\||\s)requestClientApplication=({app}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"service_name":"({service}[^"]+)""",
    """"shared_link_id":"({resource}[^,"\s]+?)"""",
    """\smsg=({additional_info}.*?)\s\w+=""",
    """owned_by"{1,20}:.+?"login"{1,20}:"{1,20}({target_user}[^\s@"]+@[^\s@"]+)""",
    """[^\w]created_by"{1,20}\s{0,100}:\s{0,100}[^\}]+?[^\w]name"{1,20}\s{0,100}:\s{0,100}"{1,20}(Unknown User|({user_fullname}[^":,]+))[",\]\}]""",
    """[^\w]created_by"{1,20}\s{0,100}:\s{0,100}[^\}]+?[^\w]login"{1,20}\s{0,100}:\s{0,100}"{1,20}.*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))""",
    """"user":\{[^\}]+?"name":"({user_fullname}[^"]+)","email":"({user_email}[^@]+@({email_domain}[^"]+))""""
  ]
}
```