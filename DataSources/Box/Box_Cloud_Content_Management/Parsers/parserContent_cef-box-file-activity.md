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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """([^\|]{1,2000}\|){5}({access_type}[^\|]{1,2000})\|""",
    """([^\|]{1,2000}\|){5}resource\-({access_type}[^\|]{1,2000})\|""",
    """"{1,20}created_at"{1,20}:"{1,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\-\d\d:\d\d)""",
    """\sfname=({file_name}.+?(\.({file_ext}[^\.]{1,2000}?))?)(\s{1,100}\w+=|\s{0,100}$)""",   
    """\sproto=({file_ext}\w+)""",
    """\ssrc=({src_ip}[^\s]{1,2000})""",
    """"{1,20}created_by"{1,20}:\{.+?"{1,20}name"{1,20}:"{1,20}({user_fullname}[^\"]{1,2000})"{1,20}""",
    """"{1,20}additional_details"{1,20}:\{"{1,20}size"{1,20}:({file_size}\d{1,100})""",
    """\ssuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\ssuser=({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\sfileType=({file_type}\w+)""",
    """"{1,20}parent"{1,20}:\{.+?"{1,20}name"{1,20}:"{1,20}({file_parent}[^\"]{1,2000})""",
    """"{1,20}event_type"{1,20}:"{1,20}({accesses}[^\"]{1,2000})"{1,20}""",
    """(\||\s)requestClientApplication=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```