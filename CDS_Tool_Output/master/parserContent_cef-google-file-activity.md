#### Parser Content
```Java
{
Name = cef-google-file-activity
    Vendor = Google
    Lms = ArcSight
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    Conditions = ["""|Skyformation|SkyFormation Cloud Apps Security|""", """"applicationName" : "drive""""]
    Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """([^\|]+\|){5}({accesses}[^\|]+)\|""",
    """([^\|]+\|){5}resource\-({accesses}[^\|]+)\|""",
    """"time"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """\sfname=({file_name}.+?(\.({file_ext}[^\.]+?))?)(\s+\w+=|\s*$)""",
    """\sproto=({file_ext}\w+)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """"+created_by"+:\{.+?"+name"+:"+({user_fullname}[^\"]+)"+""",
    """"+additional_details"+:\{"+size"+:({file_size}\d+)""",
    """(\||\s)suser=({user_email}[^\"]+?)(\s+\w+=|[\s\"]*$)""",
    """(\||\s)sproc=({user_email}[^\"]+?)(\s+\w+=|[\s\"]*$)""",
    """\sfileType=({file_type}\w+)""",
    """"+parent"+:\{.+?"+name"+:"+({file_parent}[^\"]+)""",
    """"+event_type"+:"+({accesses}[^\"]+)"+""",
    """(\||\s)requestClientApplication=({app}.+?)(\s+\w+=|\s*$)""",
    """filePermission=({access_type}[^\s]+)""", 
  ]
  DupFields = [ "user_email->user" ]
}
```