#### Parser Content
```Java
{
Name = box-skyformation-file-activity
  Vendor = Box
  Product = Box
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|Skyformation|""", """destinationServiceName=Box""", """"item_type":"""", """"item_name":"""" ]
  Fields = [
    """"+created_at"+:"+({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d([\+\-]\d\d:\d\d)?)""",
    """exabeam_host=({host}[^\s]+)""",
    """({host}[\w\-.]+) Skyformation""",
    """\ssrc=({src_ip}[^\s]+)""",
    """created_by":.+?"login":"(anonymous|({user}[^\s@"]+))""",
    """created_by":.+?"login":"({user_email}[^\s@"]+@[^\s@"]+)""",
    """\ssuser=(anonymous|({user}[^\s@"]+))\s+(\w+=|$)""",
    """\ssuser=({user_email}[^\s@]+@[^\s@]+)\s+(\w+=|$)""",
    """"item_name":"({file_name}[^\.]+?)",""""
    """"item_name":"([^\.]+?|(({file_name}[^"]+?)\.(|({file_ext}[^\."]+?))))",""""    
    """"item_type":"({file_type}[^"]+)""",
    """\sfname=({file_name}.+?)\s+(\w+=|$)""",
    """"parent":\{[^\}]*?"name":"({file_parent}[^"]+)""",
    """"event_type":"({accesses}[^"]+)""",
    """additional_details":\{[^\}]*?"size":({bytes}\d+)""",
    """(\||\s)requestClientApplication=({app}.+?)(\s+\w+=|\s*$)""",
    """"service_name":"({service}[^"]+)""",
    """"shared_link_id":"({resource}[^,"\s]+?)"""",
    """\smsg=({additional_info}.*?)\s\w+=""",
    """owned_by"+:.+?"login"+:"+({target_user}[^\s@"]+@[^\s@"]+)""",
    """[^\w]created_by"+\s*:\s*[^\}]+?[^\w]name"+\s*:\s*"+({user_fullname}[^":,]+)[",\]\}]""",
    """[^\w]created_by"+\s*:\s*[^\}]+?[^\w]login"+\s*:\s*"+.*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))""",
  ]
}
```