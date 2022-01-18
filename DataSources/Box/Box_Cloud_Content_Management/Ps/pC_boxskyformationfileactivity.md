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
  Conditions = [ """|Skyformation|""", """destinationServiceName =Box""", """"item_type":"""", """"item_name":"""" ]
  Fields = [
    """"{1,20}created_at"{1,20}:"{1,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d([\+\-]\d\d:\d\d)?)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """\ssrc=({src_ip}[^\s]{1,2000})""",
    """created_by":[^\}]{1,2000}?"login":"(anonymous|Unknown User|({user}[^\s@"]{1,2000}))""",
    """created_by":[^\}]{1,2000}?"login":"({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000})""",
    """\ssuser=(anonymous|({user}[^\s@"]{1,2000}))\s{1,100}(\w+=|$)""",
    """\ssuser=({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """"item_name":"({file_name}[^\.]{1,2000}?)",""""
    """"item_name":"([^\.]{1,2000}?|(({file_name}[^"]{1,2000}?\.(|({file_ext}[^\."]{1,2000}?)))))",""""    
    """"item_type":"({file_type}[^"]{1,2000})""",
    """\sfname=({file_name}.+?)\s{1,100}(\w+=|$)""",
    """"parent":\{[^\}]{0,2000}?"name":"({file_parent}[^"]{1,2000})""",
    """"event_type":"({accesses}[^"]{1,2000})""",
    """additional_details":\{[^\}]{0,2000}?"size":({bytes}\d{1,100})""",
    """(\||\s)requestClientApplication=({app}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"service_name":"({service}[^"]{1,2000})""",
    """"shared_link_id":"({resource}[^,"\s]{1,2000}?)"""",
    """\smsg=({additional_info}.*?)\s\w+=""",
    """owned_by"{1,20}:.+?"login"{1,20}:"{1,20}({target_user}[^\s@"]{1,2000}@[^\s@"]{1,2000})""",
    """[^\w]created_by"{1,20}\s{0,100}:\s{0,100}[^\}]{1,2000}?[^\w]name"{1,20}\s{0,100}:\s{0,100}"{1,20}(Unknown User|({user_fullname}[^":,]{1,2000}))[",\]\}]""",
    """[^\w]created_by"{1,20}\s{0,100}:\s{0,100}[^\}]{1,2000}?[^\w]login"{1,20}\s{0,100}:\s{0,100}"{1,20}.*?@([\.\w+]{1,2000}\.)?({email_domain}[^\.\s]{1,2000}\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))""",
    """"user":\{[^\}]{1,2000}?"name":"({user_fullname}[^"]{1,2000})","email":"({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))""""
  ]


}
```