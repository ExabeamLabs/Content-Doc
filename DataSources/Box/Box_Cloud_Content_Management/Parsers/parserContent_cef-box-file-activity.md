#### Parser Content
```Java
{
Name = cef-box-file-activity
    Vendor = Box
    Product = Box Cloud Content Management
    Lms = ArcSight
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = ["""|Skyformation|BOX EXABEAM|""","""fname=""","""msg="""]
    Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """([^\|]+\|){5}({access_type}[^\|]+)\|""",
    """([^\|]+\|){5}resource\-({access_type}[^\|]+)\|""",
    """"+created_at"+:"+({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\-\d\d:\d\d)""",
    """\sfname=({file_name}.+?(\.({file_ext}[^\.]+?))?)(\s+\w+=|\s*$)""",   
    """\sproto=({file_ext}\w+)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """"+created_by"+:\{.+?"+name"+:"+({user_fullname}[^\"]+)"+""",
    """"+additional_details"+:\{"+size"+:({file_size}\d+)""",
    """\ssuser=({user}.+?)\s+(\w+=|$)""",
    """\ssuser=({user_email}[^\s@]+@[^\s@]+)\s+(\w+=|$)""",
    """\sfileType=({file_type}\w+)""",
    """"+parent"+:\{.+?"+name"+:"+({file_parent}[^\"]+)""",
    """"+event_type"+:"+({accesses}[^\"]+)"+""",
    """(\||\s)requestClientApplication=({app}.+?)(\s+\w+=|\s*$)""",
  ]
}
```