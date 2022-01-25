#### Parser Content
```Java
{
Name = cef-ping-auth-failed-3
  DataType = "authentication-failed"
  Conditions = [ """CEF:""", """|Ping Identity|PingFederate|""", """|STS|STS|""", """msg=failure""" ]

cef-ping-events-1 = {
  Vendor = Ping Identity
  Product = Ping Identity
  Lms = ArcSight
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Fields = [
    """\Wrt=({time}\w+\.? \d{1,100} \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wduid=({user}[^\s@\\\=]{1,2000}?)[\\\=]{0,2000}\s{1,100}(\w+=|$)""",
    """\Wduid=({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})""",
    """\Wcs2=(|({connection_id}[^=]{1,100}?))\s{1,100}(\w+=|$)""",
    """\Wcs3=(|({protocol}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\Wmsg=(|({outcome}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\|Ping Identity\|PingFederate\|([^\|]{0,200}){3}\|({event_name}[^\|]{1,200})""",
    """cs6=(|({additional_info}[^"]{1,2000}?))\s{1,100}(\w+=|$)""",
  
}
```