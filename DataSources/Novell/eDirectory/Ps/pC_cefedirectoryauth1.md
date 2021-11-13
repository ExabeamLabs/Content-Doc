#### Parser Content
```Java
{
Name = cef-edirectory-auth-1
  DataType = "authentication-successful"
  Conditions = [ """CEF:""", """|eDirectory|eDirectory|""", """|LOGIN|""" ]

cef-edirectory-events = {
  Vendor = Novell
  Product = eDirectory
  Lms = ArcSight
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """\Wrt=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100} \d\d:\d\d:\d\d)""",
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wsuser=CN\\=({src_host}[\w\-.]{1,2000})""",
    """\Wduser=CN\\=({user_fullname}[^,]{1,2000}),({user_ou}OU\\=.+?)\s{1,100}(\w+=|$)""",
    """\Woutcome=({outcome}\w+)""",
    """\Wcs1=(({protocol}\w+):\s{0,100})?({dest_ip}[A-Fa-f:\d.]{1,2000}?):({dest_port}\d{1,100})""",
  
}
```