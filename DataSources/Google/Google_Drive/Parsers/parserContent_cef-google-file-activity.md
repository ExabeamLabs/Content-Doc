#### Parser Content
```Java
{
Name = cef-google-file-activity
    Vendor = Google
  Product = Google Drive
    Lms = ArcSight
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    Conditions = ["""|Skyformation|SkyFormation Cloud Apps Security|""", """"applicationName" : "drive""""]
    Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """([^\|]+\|){5}({accesses}[^\|]+)\|""",
    """([^\|]+\|){5}resource\-({accesses}[^\|]+)\|""",
    """"time"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """\sfname=({file_name}.+?(\.({file_ext}[^\.]+?))?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sproto=({file_ext}\w+)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """"{1,20}created_by"{1,20}:\{.+?"{1,20}name"{1,20}:"{1,20}({user_fullname}[^\"]+)"{1,20}""",
    """"{1,20}additional_details"{1,20}:\{"{1,20}size"{1,20}:({file_size}\d{1,100})""",
    """(\||\s)suser=({user_email}[^\"]+?)(\s{1,100}\w+=|[\s\"]*$)""",
    """(\||\s)sproc=({user_email}[^\"]+?)(\s{1,100}\w+=|[\s\"]*$)""",
    """\sfileType=({file_type}\w+)""",
    """"{1,20}parent"{1,20}:\{.+?"{1,20}name"{1,20}:"{1,20}({file_parent}[^\"]+)""",
    """"{1,20}event_type"{1,20}:"{1,20}({accesses}[^\"]+)"{1,20}""",
    """(\||\s)requestClientApplication=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """filePermission=({access_type}[^\s]+)""", 
  ]
  DupFields = [ "user_email->user" ]
}
```