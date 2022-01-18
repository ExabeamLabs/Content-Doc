#### Parser Content
```Java
{
Name = cef-ping-auth-successful-1
  DataType = "authentication-successful"
  Conditions = [ """CEF:""", """|Ping Identity|PingFederate|""", """|AUTHN_ATTEMPT|""", """msg=success""" ]

cef-ping-events-1 = {
  Vendor = Ping Identity
  Product = Ping Identity
  Lms = ArcSight
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Fields = [
    """\Wrt=({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wduid=({user}[^\s@\\\=]{1,2000}?)[\\\=]{0,2000}\s{1,100}(\w+=|$)""",
    """\Wduid=({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})""",
    """\Wcs2=(|({app}.+?))\s{1,100}(\w+=|$)""",
    """\Wcs3=(|({protocol}.+?))\s{1,100}(\w+=|$)""",
    """\Wmsg=(|({outcome}.+?))\s{1,100}(\w+=|$)""",
  
}
```